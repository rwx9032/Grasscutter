package emu.grasscutter.server.http.dispatch;

import com.google.protobuf.ByteString;
import emu.grasscutter.Grasscutter;
import emu.grasscutter.Grasscutter.ServerRunMode;
import emu.grasscutter.net.proto.QueryCurrRegionHttpRspOuterClass.QueryCurrRegionHttpRsp;
import emu.grasscutter.net.proto.RegionInfoOuterClass.RegionInfo;
import emu.grasscutter.net.proto.ResVersionConfigOuterClass.ResVersionConfig;
import emu.grasscutter.net.proto.RegionSimpleInfoOuterClass.RegionSimpleInfo;
import emu.grasscutter.server.event.dispatch.QueryAllRegionsEvent;
import emu.grasscutter.server.event.dispatch.QueryCurrentRegionEvent;
import emu.grasscutter.server.http.Router;
import emu.grasscutter.server.http.objects.QueryCurRegionRspJson;
import emu.grasscutter.utils.Crypto;
import emu.grasscutter.utils.Utils;
import io.javalin.Javalin;
import io.javalin.http.Context;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.security.Signature;
import java.util.regex.Pattern;

import static emu.grasscutter.config.Configuration.*;
import static emu.grasscutter.net.proto.QueryRegionListHttpRspOuterClass.QueryRegionListHttpRsp;

/**
 * Handles requests related to region queries.
 */
public final class RegionHandler implements Router {
    private static final Map<String, RegionData> regions = new ConcurrentHashMap<>();
    private static String regionListResponse;

    public RegionHandler() {
        try { // Read & initialize region data.
            this.initialize();
        } catch (Exception exception) {
            Grasscutter.getLogger().error("Failed to initialize region data.", exception);
        }
    }

    /**
     * Configures region data according to configuration.
     */
    private void initialize() {
        String dispatchDomain = "http" + (HTTP_ENCRYPTION.useInRouting ? "s" : "") + "://"
                + lr(HTTP_INFO.accessAddress, HTTP_INFO.bindAddress) + ":"
                + lr(HTTP_INFO.accessPort, HTTP_INFO.bindPort);

        // Create regions.
        List<RegionSimpleInfo> servers = new ArrayList<>();
        List<String> usedNames = new ArrayList<>(); // List to check for potential naming conflicts.

        var configuredRegions = new ArrayList<>(List.of(DISPATCH_INFO.regions));
        if (SERVER.runMode != ServerRunMode.HYBRID && configuredRegions.size() == 0) {
            Grasscutter.getLogger().error("[Dispatch] There are no game servers available. Exiting due to unplayable state.");
            System.exit(1);
        } else if (configuredRegions.size() == 0)
            configuredRegions.add(new Region("os_usa", DISPATCH_INFO.defaultName,
                    lr(GAME_INFO.accessAddress, GAME_INFO.bindAddress),
                    lr(GAME_INFO.accessPort, GAME_INFO.bindPort)));

        configuredRegions.forEach(region -> {
            if (usedNames.contains(region.Name)) {
                Grasscutter.getLogger().error("Region name already in use.");
                return;
            }

            // Create a region identifier.
            var identifier = RegionSimpleInfo.newBuilder()
                    .setName(region.Name).setTitle(region.Title).setType("DEV_PUBLIC")
                    .setDispatchUrl(dispatchDomain + "/query_cur_region/" + region.Name)
                    .build();
            usedNames.add(region.Name); servers.add(identifier);

			//var Base64ResVersionConfigMd5 = "e1wicmVtb3RlTmFtZVwiOiBcInJlc192ZXJzaW9uc19leHRlcm5hbFwiLCBcIm1kNVwiOiBcImQ0YzdjZWY2ZGVkNDA1NmUxZjY5MWVkMWM4YzYwMDBhXCIsIFwiZmlsZVNpemVcIjogMzI2MDU2fVxyXG57XCJyZW1vdGVOYW1lXCI6IFwicmVzX3ZlcnNpb25zX21lZGl1bVwiLCBcIm1kNVwiOiBcIjA4YWIyOWE0NzlhOTM4MjQyMDU3NDg3MmYzZjUwYzk0XCIsIFwiZmlsZVNpemVcIjogOTczNDV9XHJcbntcInJlbW90ZU5hbWVcIjogXCJyZXNfdmVyc2lvbnNfc3RyZWFtaW5nXCIsIFwibWQ1XCI6IFwiYjIyMTVlYTRkNzBiODJjMGI4NWM1MzVkMzczMmRiOGVcIiwgXCJmaWxlU2l6ZVwiOiAyOTM2MH1cclxue1wicmVtb3RlTmFtZVwiOiBcInJlbGVhc2VfcmVzX3ZlcnNpb25zX2V4dGVybmFsXCIsIFwibWQ1XCI6IFwiODgzYzg2ZGYyN2FiMTAwZDA0YzFmMDhkNzc5NDAxYTJcIiwgXCJmaWxlU2l6ZVwiOiAzMjYwNTZ9XHJcbntcInJlbW90ZU5hbWVcIjogXCJyZWxlYXNlX3Jlc192ZXJzaW9uc19tZWRpdW1cIiwgXCJtZDVcIjogXCI0ZjczMDAxZTQzZDE4NTEwZWVlYzNmZTUyZjhkMDA4OFwiLCBcImZpbGVTaXplXCI6IDk3MzQ1fVxyXG57XCJyZW1vdGVOYW1lXCI6IFwicmVsZWFzZV9yZXNfdmVyc2lvbnNfc3RyZWFtaW5nXCIsIFwibWQ1XCI6IFwiY2IwMDRkZjY4NTkzYjFkODVmMzZjN2UxMzAzOGVmNTJcIiwgXCJmaWxlU2l6ZVwiOiAyOTM2MH1cclxue1wicmVtb3RlTmFtZVwiOiBcImJhc2VfcmV2aXNpb25cIiwgXCJtZDVcIjogXCIzN2NkNmY3OGJmMmJkMTllODY4YTdhZGNiOTY0ZjZlZlwiLCBcImZpbGVTaXplXCI6IDE4fQ==";
            //var ResVersionConfigMd5 = "";
            var ResVersionConfigMd5 = "{\"remoteName\": \"res_versions_external\", \"md5\": \"d4c7cef6ded4056e1f691ed1c8c6000a\", \"fileSize\": 326056}\r\n{\"remoteName\": \"res_versions_medium\", \"md5\": \"08ab29a479a9382420574872f3f50c94\", \"fileSize\": 97345}\r\n{\"remoteName\": \"res_versions_streaming\", \"md5\": \"b2215ea4d70b82c0b85c535d3732db8e\", \"fileSize\": 29360}\r\n{\"remoteName\": \"release_res_versions_external\", \"md5\": \"883c86df27ab100d04c1f08d779401a2\", \"fileSize\": 326056}\r\n{\"remoteName\": \"release_res_versions_medium\", \"md5\": \"4f73001e43d18510eeec3fe52f8d0088\", \"fileSize\": 97345}\r\n{\"remoteName\": \"release_res_versions_streaming\", \"md5\": \"cb004df68593b1d85f36c7e13038ef52\", \"fileSize\": 29360}\r\n{\"remoteName\": \"base_revision\", \"md5\": \"37cd6f78bf2bd19e868a7adcb964f6ef\", \"fileSize\": 18}";
            //String ResVersionConfigMd5 = Base64.getEncoder().withoutPadding().encodeToString(Base64ResVersionConfigMd5.getBytes());

            // Create a ResVersionConfig object.
            var resVersionConfig = ResVersionConfig.newBuilder()
                    .setVersion(10283122)
                    .setMd5(ResVersionConfigMd5)
                    .setVersionSuffix("ec58ff372e")
                    .setBranch("3.0_live")
                    .setReleaseTotalSize("0")
                    .build();

            // aBuilder.getB1Builder().setB("convenint_set")
            // Create a region info object.
            var regionInfo = RegionInfo.newBuilder()
                    .setGateserverIp(region.Ip).setGateserverPort(region.Port).setAreaType("CN")
                    .setSecretKey(ByteString.copyFrom(Crypto.DISPATCH_SEED))
                    .setClientDataVersion(10316937)
                    .setClientSilenceDataVersion(10446836)
                    .setClientVersionSuffix("4fcac11e23")
                    .setClientSilenceVersionSuffix("320895326e")
                    .setClientDataMd5("{\"remoteName\": \"data_versions\", \"md5\": \"a6c06d1ce216776cac26797cf60c8133\", \"fileSize\": 4414}")
                    .setClientSilenceDataMd5("{\"remoteName\": \"data_versions\", \"md5\": \"10c4b8f1188a624c5d44eddbb2ce8479\", \"fileSize\": 513}")
                    .setResourceUrlBak("3.0_live")
                    .setResourceUrl("https://autopatchcn.yuanshen.com/client_game_res/3.0_live")
                    .setDataUrl("https://autopatchcn.yuanshen.com/client_design_data/3.0_live")
                    .setResVersionConfig(resVersionConfig)
                    .build();
            //output region info
            Grasscutter.getLogger().info("Region info: " + regionInfo.toString());
            // Create an updated region query.
            var updatedQuery = QueryCurrRegionHttpRsp.newBuilder().setRegionInfo(regionInfo).build();
            regions.put(region.Name, new RegionData(updatedQuery, Utils.base64Encode(updatedQuery.toByteString().toByteArray())));
        });

        // Create a config object.
        byte[] customConfig = "{\"sdkenv\":\"2\",\"checkdevice\":\"false\",\"loadPatch\":\"false\",\"showexception\":\"false\",\"regionConfig\":\"pm|fk|add\",\"downloadMode\":\"0\"}".getBytes();
        Crypto.xor(customConfig, Crypto.DISPATCH_KEY); // XOR the config with the key.

        // Create an updated region list.
        QueryRegionListHttpRsp updatedRegionList = QueryRegionListHttpRsp.newBuilder()
                .addAllRegionList(servers)
                .setClientSecretKey(ByteString.copyFrom(Crypto.DISPATCH_SEED))
                .setClientCustomConfigEncrypted(ByteString.copyFrom(customConfig))
                .setEnableLoginPc(true).build();

        // Set the region list response.
        regionListResponse = Utils.base64Encode(updatedRegionList.toByteString().toByteArray());
    }

    @Override public void applyRoutes(Javalin javalin) {
        javalin.get("/query_region_list", RegionHandler::queryRegionList);
        javalin.get("/query_cur_region/{region}", RegionHandler::queryCurrentRegion );
    }

    /**
     * @route /query_region_list
     */
    private static void queryRegionList(Context ctx) {
        // Invoke event.
        QueryAllRegionsEvent event = new QueryAllRegionsEvent(regionListResponse); event.call();
        // Respond with event result.
        ctx.result(event.getRegionList());

        // Log to console.
        Grasscutter.getLogger().info(String.format("[Dispatch] Client %s request: query_region_list", ctx.ip()));
    }

    /**
     * @route /query_cur_region/{region}
     */
    private static void queryCurrentRegion(Context ctx) {
        // Get region to query.
        String regionName = ctx.pathParam("region");
        String versionName = ctx.queryParam("version");
        var region = regions.get(regionName);

        // Get region data.
        String regionData = "CAESGE5vdCBGb3VuZCB2ZXJzaW9uIGNvbmZpZw==";
        if (ctx.queryParamMap().values().size() > 0) {
            if (region != null)
                regionData = region.getBase64();
        }

        String[] versionCode = versionName.replaceAll(Pattern.compile("[a-zA-Z]").pattern(), "").split("\\.");
        int versionMajor = Integer.parseInt(versionCode[0]);
        int versionMinor = Integer.parseInt(versionCode[1]);
        int versionFix   = Integer.parseInt(versionCode[2]);

        if (versionMajor >= 3 || (versionMajor == 2 && versionMinor == 7 && versionFix >= 50) || (versionMajor == 2 && versionMinor == 8)) {
            try {
                QueryCurrentRegionEvent event = new QueryCurrentRegionEvent(regionData); event.call();

                if (ctx.queryParam("dispatchSeed") == null) {
                    // More love for UA Patch players
                    var rsp = new QueryCurRegionRspJson();

                    rsp.content = event.getRegionInfo();
                    rsp.sign = "TW9yZSBsb3ZlIGZvciBVQSBQYXRjaCBwbGF5ZXJz";

                    ctx.json(rsp);
                    return;
                }

                String key_id = ctx.queryParam("key_id");
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key_id.equals("3") ? Crypto.CUR_OS_ENCRYPT_KEY : Crypto.CUR_CN_ENCRYPT_KEY);
                var regionInfo = Utils.base64Decode(event.getRegionInfo());

                //Encrypt regionInfo in chunks
                ByteArrayOutputStream encryptedRegionInfoStream = new ByteArrayOutputStream();

                //Thank you so much GH Copilot
                int chunkSize = 256 - 11;
                int regionInfoLength = regionInfo.length;
                int numChunks = (int) Math.ceil(regionInfoLength / (double) chunkSize);

                for (int i = 0; i < numChunks; i++) {
                    byte[] chunk = Arrays.copyOfRange(regionInfo, i * chunkSize, Math.min((i + 1) * chunkSize, regionInfoLength));
                    byte[] encryptedChunk = cipher.doFinal(chunk);
                    encryptedRegionInfoStream.write(encryptedChunk);
                }

                Signature privateSignature = Signature.getInstance("SHA256withRSA");
                privateSignature.initSign(Crypto.CUR_SIGNING_KEY);
                privateSignature.update(regionInfo);

                var rsp = new QueryCurRegionRspJson();

                rsp.content = Utils.base64Encode(encryptedRegionInfoStream.toByteArray());
                rsp.sign = Utils.base64Encode(privateSignature.sign());

                ctx.json(rsp);
            }
            catch (Exception e) {
                Grasscutter.getLogger().error("An error occurred while handling query_cur_region.", e);
            }
        }
        else {
            // Invoke event.
            QueryCurrentRegionEvent event = new QueryCurrentRegionEvent(regionData); event.call();
            // Respond with event result.
            ctx.result(event.getRegionInfo());
        }
        // Log to console.
        Grasscutter.getLogger().info(String.format("Client %s request: query_cur_region/%s", ctx.ip(), regionName));
    }

    /**
     * Region data container.
     */
    public static class RegionData {
        private final QueryCurrRegionHttpRsp regionQuery;
        private final String base64;

        public RegionData(QueryCurrRegionHttpRsp prq, String b64) {
            this.regionQuery = prq;
            this.base64 = b64;
        }

        public QueryCurrRegionHttpRsp getRegionQuery() {
            return this.regionQuery;
        }

        public String getBase64() {
            return this.base64;
        }
    }

    /**
     * Gets the current region query.
     * @return A {@link QueryCurrRegionHttpRsp} object.
     */
    public static QueryCurrRegionHttpRsp getCurrentRegion() {
        return SERVER.runMode == ServerRunMode.HYBRID ? regions.get("os_usa").getRegionQuery() : null;
    }
}
