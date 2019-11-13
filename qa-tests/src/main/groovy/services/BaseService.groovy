package services

import io.grpc.ManagedChannel
import io.grpc.netty.NegotiationType
import io.grpc.netty.NettyChannelBuilder
import util.Env

class BaseService {

    static ManagedChannel channelInstance = null

    static initializeChannel() {
        channelInstance = NettyChannelBuilder
                        .forAddress(Env.mustGetHostname(), Env.mustGetPort())
                        .negotiationType(NegotiationType.TLS)
                        .build()
    }

    static getChannel() {
        initializeChannel()
        return channelInstance
    }
}
