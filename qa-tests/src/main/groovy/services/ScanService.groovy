package services

import io.stackrox.proto.api.v1.ScanServiceGrpc
import io.stackrox.proto.api.v1.ScanServiceOuterClass
import io.stackrox.proto.api.v1.ScanServiceOuterClass.ImageSpec
import io.stackrox.proto.api.v1.ScanServiceOuterClass.ScanImageRequest.RegistryData

class ScanService extends BaseService {
    static getScanClient() {
        return ScanServiceGrpc.newBlockingStub(getChannel())
    }

    static scanImage(String image, RegistryData registryData) {
        try {
            return getScanClient().scanImage(ScanServiceOuterClass.ScanImageRequest.newBuilder()
                    .setImage(image)
                    .setRegistry(registryData)
                    .build())
        } catch (Exception e) {
            println "Error trying to submit image for scan: ${e.toString()}"
        }
    }

    static getScan(ImageSpec imageSpec) {
        return getScanClient().getScan(
                ScanServiceOuterClass.GetScanRequest.newBuilder()
                        .setImageSpec(imageSpec)
                        .build())
    }

    static getLanguageLevelComponents(ImageSpec imageSpec) {
        return getScanClient().getLanguageLevelComponents(
                ScanServiceOuterClass.GetLanguageLevelComponentsRequest.newBuilder()
                        .setImageSpec(imageSpec)
                        .build())
    }
}
