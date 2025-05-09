// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.
// source: scanner/api/v1/node_scan_service.proto

/*
Package scannerV1 is a reverse proxy.

It translates gRPC into RESTful JSON APIs.
*/
package scannerV1

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/grpc-ecosystem/grpc-gateway/v2/utilities"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Suppress "imported and not used" errors
var (
	_ codes.Code
	_ io.Reader
	_ status.Status
	_ = errors.New
	_ = runtime.String
	_ = utilities.NewDoubleArray
	_ = metadata.Join
)

var filter_NodeScanService_GetNodeVulnerabilities_0 = &utilities.DoubleArray{Encoding: map[string]int{}, Base: []int(nil), Check: []int(nil)}

func request_NodeScanService_GetNodeVulnerabilities_0(ctx context.Context, marshaler runtime.Marshaler, client NodeScanServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var (
		protoReq GetNodeVulnerabilitiesRequest
		metadata runtime.ServerMetadata
	)
	io.Copy(io.Discard, req.Body)
	if err := req.ParseForm(); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := runtime.PopulateQueryParameters(&protoReq, req.Form, filter_NodeScanService_GetNodeVulnerabilities_0); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	msg, err := client.GetNodeVulnerabilities(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err
}

func local_request_NodeScanService_GetNodeVulnerabilities_0(ctx context.Context, marshaler runtime.Marshaler, server NodeScanServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var (
		protoReq GetNodeVulnerabilitiesRequest
		metadata runtime.ServerMetadata
	)
	if err := req.ParseForm(); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := runtime.PopulateQueryParameters(&protoReq, req.Form, filter_NodeScanService_GetNodeVulnerabilities_0); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	msg, err := server.GetNodeVulnerabilities(ctx, &protoReq)
	return msg, metadata, err
}

// RegisterNodeScanServiceHandlerServer registers the http handlers for service NodeScanService to "mux".
// UnaryRPC     :call NodeScanServiceServer directly.
// StreamingRPC :currently unsupported pending https://github.com/grpc/grpc-go/issues/906.
// Note that using this registration option will cause many gRPC library features to stop working. Consider using RegisterNodeScanServiceHandlerFromEndpoint instead.
// GRPC interceptors will not work for this type of registration. To use interceptors, you must use the "runtime.WithMiddlewares" option in the "runtime.NewServeMux" call.
func RegisterNodeScanServiceHandlerServer(ctx context.Context, mux *runtime.ServeMux, server NodeScanServiceServer) error {
	mux.Handle(http.MethodGet, pattern_NodeScanService_GetNodeVulnerabilities_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		annotatedContext, err := runtime.AnnotateIncomingContext(ctx, mux, req, "/scannerV1.NodeScanService/GetNodeVulnerabilities", runtime.WithHTTPPathPattern("/v1/nodes/vulnerabilities"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_NodeScanService_GetNodeVulnerabilities_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}
		forward_NodeScanService_GetNodeVulnerabilities_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)
	})

	return nil
}

// RegisterNodeScanServiceHandlerFromEndpoint is same as RegisterNodeScanServiceHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterNodeScanServiceHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	conn, err := grpc.NewClient(endpoint, opts...)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				grpclog.Errorf("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				grpclog.Errorf("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()
	return RegisterNodeScanServiceHandler(ctx, mux, conn)
}

// RegisterNodeScanServiceHandler registers the http handlers for service NodeScanService to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterNodeScanServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterNodeScanServiceHandlerClient(ctx, mux, NewNodeScanServiceClient(conn))
}

// RegisterNodeScanServiceHandlerClient registers the http handlers for service NodeScanService
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "NodeScanServiceClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "NodeScanServiceClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "NodeScanServiceClient" to call the correct interceptors. This client ignores the HTTP middlewares.
func RegisterNodeScanServiceHandlerClient(ctx context.Context, mux *runtime.ServeMux, client NodeScanServiceClient) error {
	mux.Handle(http.MethodGet, pattern_NodeScanService_GetNodeVulnerabilities_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		annotatedContext, err := runtime.AnnotateContext(ctx, mux, req, "/scannerV1.NodeScanService/GetNodeVulnerabilities", runtime.WithHTTPPathPattern("/v1/nodes/vulnerabilities"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_NodeScanService_GetNodeVulnerabilities_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}
		forward_NodeScanService_GetNodeVulnerabilities_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)
	})
	return nil
}

var (
	pattern_NodeScanService_GetNodeVulnerabilities_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"v1", "nodes", "vulnerabilities"}, ""))
)

var (
	forward_NodeScanService_GetNodeVulnerabilities_0 = runtime.ForwardResponseMessage
)
