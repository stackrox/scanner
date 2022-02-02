package ioutils

import (
	"container/list"
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/concurrency"
)

type reservationResponse struct {
	buf *Buffer
	err error
}

type reservationRequest struct {
	bytesRequested int
	responseChan   chan<- *reservationResponse
	cancelSig      *concurrency.Signal
}

type freeRequest struct {
	buf *Buffer
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
	stopped concurrency.Flag
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

func (b *BufferPool) cleanupCanceledReservations() {
	elem := b.reservationQueue.Front()
	for elem != nil {
		nextElem := elem.Next()
		resReq := elem.Value.(*reservationRequest)
		if resReq.cancelSig.IsDone() {
			b.reservationQueue.Remove(elem)
		}
		elem = nextElem
	}
}

func (b *BufferPool) manageReservations() {
	for {
		select {
		case <-b.stopSig.Done():
			b.stopped.Set(true)
			return
		case resReq := <-b.reservationChan:
			b.cleanupCanceledReservations()
			// If there are reservations, just add this one to the queue
			if b.reservationQueue.Len() > 0 {
				b.reservationQueue.PushBack(resReq)
				continue
			}
			numBuffersRequired := resReq.bytesRequested / b.denominationBytes
			if resReq.bytesRequested%b.denominationBytes != 0 {
				numBuffersRequired++
			}
			// Great, we can fill the request!
			if b.freeBufferIndexes.Len() > numBuffersRequired {
				indexesForBuffer := make([]int, 0, numBuffersRequired)
				elem := b.freeBufferIndexes.Front()
				for i := 0; i < numBuffersRequired; i++ {
					indexesForBuffer = append(indexesForBuffer, elem.Value.(int))
					nextElem := elem.Next()
					b.freeBufferIndexes.Remove(elem)
					elem = nextElem
				}
				buf := &Buffer{pool: b, heldBufferIndexes: indexesForBuffer}
				select {
				case resReq.responseChan <- &reservationResponse{buf: buf}:
				case <-resReq.cancelSig.Done():
				}
			}
		case freeReq := <-b.freeChan:
			_ = freeReq
		}
	}
}

func (b *BufferPool) Stop() {
	b.stopSig.Signal()
}

func (b *BufferPool) Make(ctx context.Context, capacity int) (*Buffer, error) {
	responseChan := make(chan *reservationResponse)
	cancelSig := concurrency.NewSignal()
	select {
	case b.reservationChan <- &reservationRequest{bytesRequested: capacity, responseChan: responseChan, cancelSig: &cancelSig}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-ctx.Done():
		// TODO: clean up request
		return nil, ctx.Err()
	case resp := <-responseChan:
		return resp.buf, resp.err
	}
}

func (b *BufferPool) Free(ctx context.Context, buffer *Buffer) {
	select {
	case b.freeChan <- &freeRequest{buffer}:
	case <-ctx.Done():
		return
	}
}

type Buffer struct {
	pool              *BufferPool
	heldBufferIndexes []int
}
