package ioutils

import (
	"container/list"
	"context"

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
	bytesRequested int
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

	freeBufferIndexes *list.List // will be a list of int

	totalSizeBytes    int
	denominationBytes int

	stopSig concurrency.Signal
}

func NewBufferPool(totalSizeBytes, denominationBytes int) (*BufferPool, error) {
	if totalSizeBytes <= 0 || denominationBytes <= 0 {
		return nil, errors.New("total size and denomination must both be >0")
	}
	if totalSizeBytes%denominationBytes != 0 {
		return nil, errors.New("total size must be an exact multiple of the denomination")
	}

	numBuffers := totalSizeBytes / denominationBytes
	b := &BufferPool{
		denominationBytes: denominationBytes,
		underlyingBuffers: make([][]byte, numBuffers),
		freeBufferIndexes: list.New(),
	}
	for i := 0; i < numBuffers; i++ {
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
	if b.freeBufferIndexes.Len() < numBuffersRequired {
		return false
	}
	indexesForBuffer := make([]int, 0, numBuffersRequired)
	elem := b.freeBufferIndexes.Front()
	for i := 0; i < numBuffersRequired; i++ {
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

func (b *BufferPool) Alloc(ctx context.Context, capacity int) ([]int, error) {
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
					b.Free(resp.indexesReleased)
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

func (b *BufferPool) Free(indexes []int) {
	select {
	case b.freeChan <- &freeRequest{indexesToFree: indexes}:
	case <-b.stopSig.Done():
	}
}

type Buffer struct {
	pool              *BufferPool
	heldBufferIndexes []int
}
