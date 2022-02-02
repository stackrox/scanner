package ioutils

import (
	"container/list"
	"context"
	"io"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/concurrency"
)

var (
	ErrBufferPoolStopped = errors.New("buffer pool was stopped")
)

type reservationResponse struct {
	indexesReleased []int
	err             error
}

type reservationRequest struct {
	bytesRequested int64
	responseChan   chan<- *reservationResponse
	cancelSig      *concurrency.Signal
}

type freeRequest struct {
	indexesToFree []int
}

type BufferPool struct {
	underlyingBuffers [][]byte

	reservationQueue list.List // list of *reservationRequest

	reservationChan chan *reservationRequest
	freeChan        chan *freeRequest

	freeBufferIndexes list.List // will be a list of int

	totalSizeBytes    int64
	denominationBytes int64

	stopSig concurrency.Signal
}

func NewBufferPool(totalSizeBytes, denominationBytes int64) (*BufferPool, error) {
	if totalSizeBytes <= 0 || denominationBytes <= 0 {
		return nil, errors.New("total size and denomination must both be >0")
	}
	if totalSizeBytes%denominationBytes != 0 {
		return nil, errors.New("total size must be an exact multiple of the denomination")
	}

	numBuffers := totalSizeBytes / denominationBytes
	b := &BufferPool{
		underlyingBuffers: make([][]byte, numBuffers),

		reservationChan: make(chan *reservationRequest),
		freeChan:        make(chan *freeRequest, 5),

		totalSizeBytes:    totalSizeBytes,
		denominationBytes: denominationBytes,

		stopSig: concurrency.NewSignal(),
	}
	for i := 0; int64(i) < numBuffers; i++ {
		b.underlyingBuffers[i] = make([]byte, denominationBytes)
		b.freeBufferIndexes.PushBack(i)
	}
	go b.manageReservations()
	return b, nil
}

func (b *BufferPool) fulfillRequestIfPossible(resReq *reservationRequest) (requestProcessed bool) {
	// If the request was canceled, remove it.
	if resReq.cancelSig.IsDone() {
		close(resReq.responseChan)
		return true
	}

	numBuffersRequired := resReq.bytesRequested / b.denominationBytes
	if resReq.bytesRequested%b.denominationBytes != 0 {
		numBuffersRequired++
	}
	// We cannot fill the request, unfortunately.
	if int64(b.freeBufferIndexes.Len()) < numBuffersRequired {
		return false
	}
	indexesForBuffer := make([]int, 0, numBuffersRequired)
	elem := b.freeBufferIndexes.Front()
	for i := int64(0); i < numBuffersRequired; i++ {
		indexesForBuffer = append(indexesForBuffer, elem.Value.(int))
		nextElem := elem.Next()
		b.freeBufferIndexes.Remove(elem)
		elem = nextElem
	}
	select {
	case resReq.responseChan <- &reservationResponse{indexesReleased: indexesForBuffer}:
		return true
	case <-resReq.cancelSig.Done():
		close(resReq.responseChan)
		// Return the indexes to the free list.
		for _, index := range indexesForBuffer {
			b.freeBufferIndexes.PushBack(index)
		}
		return true
	case <-b.stopSig.Done():
		return false
	}
}

func (b *BufferPool) fulfillAsManyRequestsAsPossible() {
	elem := b.reservationQueue.Front()
	for elem != nil {
		resReq := elem.Value.(*reservationRequest)
		requestProcessed := b.fulfillRequestIfPossible(resReq)
		// Couldn't process this request, because there isn't enough space in the queue.
		// We can't jump to the next request since we are following strict FIFO priority.
		if !requestProcessed {
			return
		}
		nextElem := elem.Next()
		b.reservationQueue.Remove(elem)
		elem = nextElem
	}
}

func (b *BufferPool) manageReservations() {
	for {
		select {
		case <-b.stopSig.Done():
			return
		case resReq := <-b.reservationChan:
			b.reservationQueue.PushBack(resReq)
			b.fulfillAsManyRequestsAsPossible()
		case freeReq := <-b.freeChan:
			for _, index := range freeReq.indexesToFree {
				b.freeBufferIndexes.PushBack(index)
			}
			b.fulfillAsManyRequestsAsPossible()
		}
	}
}

func (b *BufferPool) Stop() {
	b.stopSig.Signal()
}

func (b *BufferPool) alloc(ctx context.Context, capacity int64) ([]int, error) {
	if b.stopSig.IsDone() {
		return nil, ErrBufferPoolStopped
	}
	if capacity > b.totalSizeBytes {
		return nil, errors.Errorf("requested capacity (%d) exceeds the total capacity in the pool (%d)", capacity, b.totalSizeBytes)
	}
	responseChan := make(chan *reservationResponse)
	cancelSig := concurrency.NewSignal()
	select {
	case b.reservationChan <- &reservationRequest{bytesRequested: capacity, responseChan: responseChan, cancelSig: &cancelSig}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.stopSig.Done():
		return nil, ErrBufferPoolStopped
	}
	select {
	case <-ctx.Done():
		go func() {
			// Wait until the context closing is acknowledged by closing the channel.
			// In case there's a race, and the other goroutine sent us buffers before they realized
			// our context was closed, relinquish those buffers.
			select {
			case resp, ok := <-responseChan:
				if ok && resp.err == nil {
					b.free(resp.indexesReleased)
				}
			case <-b.stopSig.Done():
			}
		}()
		return nil, ctx.Err()
	case resp := <-responseChan:
		return resp.indexesReleased, resp.err
	case <-b.stopSig.Done():
		return nil, ErrBufferPoolStopped
	}
}

func (b *BufferPool) free(indexes []int) {
	select {
	case b.freeChan <- &freeRequest{indexesToFree: indexes}:
	case <-b.stopSig.Done():
	}
}

func (b *BufferPool) MakeBuffer() (*Buffer, error) {
	if b.stopSig.IsDone() {
		return nil, ErrBufferPoolStopped
	}
	return &Buffer{pool: b}, nil
}

var (
	errBufferFreed = errors.New("buffer was freed")
)

type Buffer struct {
	pool *BufferPool

	heldBufferIndexes []int
	length            int64

	finished bool
}

func (b *Buffer) Grow(ctx context.Context, additionalCapacity int64) error {
	if b.finished {
		return errBufferFreed
	}
	additionalIndexes, err := b.pool.alloc(ctx, additionalCapacity)
	if err != nil {
		return err
	}
	b.heldBufferIndexes = append(b.heldBufferIndexes, additionalIndexes...)
	return nil
}

func (b *Buffer) Free() {
	b.pool.free(b.heldBufferIndexes)
	b.finished = true
}

func (b *Buffer) Len() int64 {
	return b.length
}

func (b *Buffer) Cap() int64 {
	return b.pool.denominationBytes * int64(len(b.heldBufferIndexes))
}

func (b *Buffer) byteOffsetToCoordinates(byteOffset int64) (int, int64) {
	return int(byteOffset / b.pool.denominationBytes), byteOffset % b.pool.denominationBytes
}

func (b *Buffer) getBufferAt(index int) []byte {
	return b.pool.underlyingBuffers[b.heldBufferIndexes[index]]
}

func (b *Buffer) Copy(destination []byte, startingOff int64) int {
	if startingOff >= b.length {
		return 0
	}
	curBufIdx, curIdxWithinBuf := b.byteOffsetToCoordinates(startingOff)
	copiedUpto := 0
	for {
		curBuf := b.getBufferAt(curBufIdx)
		copied := copy(destination[copiedUpto:], curBuf[curIdxWithinBuf:])
		copiedUpto += copied
		// We've exhausted the buffer.
		if copied < int(b.pool.denominationBytes)-curBufIdx {
			break
		}
		if copiedUpto == len(destination) {
			break
		}
		curBufIdx++
		curIdxWithinBuf = 0
		if curBufIdx > len(b.heldBufferIndexes) {
			break
		}
	}
	return copiedUpto
}

func (b *Buffer) ReadFullFromReader(r io.Reader, startingOff, readUptoOff int64) (int, error) {
	if startingOff >= b.Cap() {
		return 0, nil
	}
	curBufIdx, curIdxWithinBuf := b.byteOffsetToCoordinates(startingOff)
	finalBufIdx, idxWithinFinalBuf := b.byteOffsetToCoordinates(readUptoOff)
	totalRead := 0
	for {
		curBuf := b.getBufferAt(curBufIdx)
		var n int
		var err error
		if curBufIdx == finalBufIdx {
			n, err = io.ReadFull(r, curBuf[curIdxWithinBuf:idxWithinFinalBuf])
		} else {
			n, err = io.ReadFull(r, curBuf[curIdxWithinBuf:])
		}
		totalRead += n
		b.length += int64(n)
		if err != nil {
			return totalRead, err
		}
		curBufIdx++
		curIdxWithinBuf = 0
		if curBufIdx > len(b.heldBufferIndexes) || curBufIdx > finalBufIdx {
			break
		}
	}
	return totalRead, nil
}
