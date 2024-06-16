#include <sw/redis++/redis++.h>
#include <iostream>
#include <jwt-cpp/jwt.h>
#include <yaml-cpp/yaml.h>

using namespace sw::redis;
using sec = std::chrono::seconds;
using min = std::chrono::minutes;

// 递归函数，用于查找指定键路径的值
std::string findKey(const YAML::Node& node, const std::string& keyPath) {
    size_t dotPos = keyPath.find('.');
    std::string currentKey = keyPath.substr(0, dotPos);
    
    if (node[currentKey]) {
        if (dotPos == std::string::npos) {
            // 已经到达最后一个键
            return node[currentKey].as<std::string>();
        } else {
            // 仍有子路径，继续递归
            return findKey(node[currentKey], keyPath.substr(dotPos + 1));
        }
    } else {
        return ""; // 未找到指定的键
    }
}

int main() {
    try {
        jwt::claim from_raw_json;
        std::istringstream iss{R"##({"api":{"array":[1,2,3],"null":null}})##"};
        iss >> from_raw_json;

        jwt::claim::set_t list{"once", "twice"};
        std::vector<int64_t> big_numbers{727663072ULL, 770979831ULL, 427239169ULL, 525936436ULL};

        const auto time = jwt::date::clock::now();
        const auto token = jwt::create()
                               .set_type("JWT")
                               .set_issuer("auth.mydomain.io")
                               .set_audience("mydomain.io")
                               .set_issued_at(time)
                               .set_not_before(time - sec{15})
                               .set_expires_at(time + sec{15} + min{2})
                               .set_payload_claim("boolean", picojson::value(true))
                               .set_payload_claim("integer", picojson::value(int64_t{12345}))
                               .set_payload_claim("precision", picojson::value(12.345))
                               .set_payload_claim("strings", jwt::claim(list))
                               .set_payload_claim("array", jwt::claim(big_numbers.begin(), big_numbers.end()))
                               .set_payload_claim("object", from_raw_json)
                               .sign(jwt::algorithm::none{});





        // 初始化 Redis 客戶端
        auto redis = Redis("tcp://127.0.0.1:6379");

        // 設置鍵值對
        redis.set("key", token);

        // 獲取鍵值對
        auto val = redis.get("key");
        if (val) {
            std::cout << "key: " << *val << std::endl;
        } else {
            std::cout << "key 不存在" << std::endl;
        }

        const auto decoded = jwt::decode(*val);

        const auto api_array = decoded.get_payload_claim("object").to_json().get("api").get("array");
        std::cout << "api array = " << api_array << std::endl;

        /* [verify exact claim] */
        jwt::verify()
            .allow_algorithm(jwt::algorithm::none{})
            .with_issuer("auth.mydomain.io")
            .with_audience("mydomain.io")
            .with_claim("object", from_raw_json) // Match the exact JSON content
            .verify(decoded);
        /* [verify exact claim] */

        YAML::Node config = YAML::LoadFile("../config.yaml");
        //std::cout << "Value of 'key': " << config["database"]["host"] << std::endl;
        std::cout << "Value of 'key': " << findKey(config, "database.host") << std::endl;
    } catch (const Error &err) {
        std::cerr << "Redis 錯誤: " << err.what() << std::endl;
    }

    return 0;
}
