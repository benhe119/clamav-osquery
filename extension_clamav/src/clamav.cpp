#include "clamav.h"

#include <cstring>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <time.h>

#include <osquery/sdk.h>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

class ClamavTablePlugin : public osquery::TablePlugin {
private:
  osquery::TableColumns columns() const override {
    return {
        std::make_tuple("path", osquery::TEXT_TYPE,
                        osquery::ColumnOptions::REQUIRED),
        std::make_tuple("filename", osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("malware", osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("malware_name", osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
    };
  }

  void clamav_scan(boost::filesystem::path path, osquery::QueryData &results,
                   const char *virname, unsigned long int size,
                   cl_engine *engine, cl_scan_options options, int ret) {
    osquery::Row r;

    // Scan the file
    ret = cl_scanfile(path.c_str(), &virname, &size, engine, &options);

    if (ret == CL_VIRUS) {
      std::string virus_name(virname);
      r["malware"] = osquery::TEXT("true");
      r["malware_name"] = osquery::TEXT(virus_name);
    } else {
      r["malware"] = osquery::TEXT("false");
      r["malware_name"] = osquery::TEXT("");
    }

    r["path"] = osquery::TEXT(path.string());
    r["filename"] = osquery::TEXT(path.filename().string());

    results.push_back(r);
  }

  osquery::QueryData generate(osquery::QueryContext &context) override {
    osquery::QueryData results;

    int ret;
    unsigned long int size = 0;
    unsigned int sigs = 0;
    const char *virname;
    struct cl_engine *engine;
    struct cl_scan_options options;

    boost::property_tree::ptree tree;
    boost::property_tree::read_json(
        "/usr/lib/osquery/extensions/clamav/config.json", tree);

    cl_init(CL_INIT_DEFAULT);
    engine = cl_engine_new();

    // Resolve file paths for EQUAL operations. Verify path is provided
    auto paths = context.constraints["path"].getAll(osquery::EQUALS);
    auto paths_like = context.constraints["path"].getAll(osquery::LIKE);

    if (paths.empty() && paths_like.empty()) {
      LOG(WARNING) << "Need path to scan";
      return {};
    }

    LOG(INFO) << "Loading signatures...";
    cl_load("/usr/lib/osquery/extensions/clamav/clamdbs/", engine, &sigs,
            CL_DB_STDOPT);
    LOG(INFO) << "Loaded: " << sigs << " signatures";
    if ((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
      LOG(ERROR) << cl_strerror(ret);
      cl_engine_free(engine);
    }
    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_HEURISTICS;

    // Resolve file paths for LIKE operations.
    context.expandConstraints(
        "path", osquery::LIKE, paths,
        ([&](const std::string &pattern, std::set<std::string> &out) {
          std::vector<std::string> patterns;
          auto status = resolveFilePattern(
              pattern, patterns, osquery::GLOB_ALL | osquery::GLOB_NO_CANON);
          if (status.ok()) {
            for (const auto &resolved : patterns) {
              out.insert(resolved);
            }
          }
          return status;
        }));

    // Iterate through each of the resolved paths.
    for (const auto &path_string : paths) {
      boost::filesystem::path path = path_string;
      LOG(INFO) << "Scanning: " << path;
      clamav_scan(path, results, virname, size, engine, options, ret);
    }

    LOG(INFO) << "Signatures released";
    cl_engine_free(engine);
    return results;
  }
};
REGISTER_EXTERNAL(ClamavTablePlugin, "table", "clamav");

// Update clam dbs
void update_clamDBs() {
  boost::property_tree::ptree tree;
  boost::property_tree::read_json(
      "/usr/lib/osquery/extensions/clamav/config.json", tree);

  std::string clamdb_path = "/usr/lib/osquery/extensions/clamav/clamdbs";
  std::string ext_dir = "/usr/lib/osquery/extensions/clamav/clamdbs";

  struct stat file_stat;
  const char *clamdb_main = clamdb_path.append("/main.cvd").c_str();
  stat(clamdb_main, &file_stat);

  struct tm *time_info = localtime(&file_stat.st_ctime);

  time_t current_time = std::time(0);

  long long file_ctime = mktime(time_info);
  long long current_sys_time = mktime(localtime(&current_time));

  // Check if main.cvd time is x days old, or if main.cvd does not exist
  if ((current_sys_time > file_ctime + tree.get<int>("time") * 24 * 60 * 60 &&
       tree.get<bool>("update")) ||
      !boost::filesystem::exists(clamdb_main)) {

    LOG(INFO) << "Its been " << tree.get<int>("time")
              << " days updating clamdbs or main.cvd does not exist in "
                 "extension directory...";

    std::string bytecode_file = ext_dir;
    std::string main_file = ext_dir;
    std::string daily_file = ext_dir;
    boost::beast::flat_buffer buffer;

    // Create clamdbs directory if it does not exist
    boost::filesystem::path dir(ext_dir.c_str());
    boost::filesystem::create_directories(dir);

    boost::asio::io_context ioc;
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv12_client);
    ctx.set_default_verify_paths();
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);

    boost::asio::ip::tcp::resolver resolver(ioc);
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(ioc, ctx);
    boost::beast::error_code ec;

    auto const results = resolver.resolve(tree.get<std::string>("url"),
                                          tree.get<std::string>("port"));

    // Download bytecode.cvd
    boost::asio::connect(stream.next_layer(), results.begin(), results.end());
    stream.handshake(boost::asio::ssl::stream_base::client);

    boost::beast::http::request<boost::beast::http::string_body> req;
    req.method(boost::beast::http::verb::get);
    req.target("/bytecode.cvd");
    req.version(11);
    req.set(boost::beast::http::field::host, tree.get<std::string>("url"));
    req.set(boost::beast::http::field::user_agent, "osquery-clamav");

    boost::beast::http::write(stream, req);
    boost::beast::http::response<boost::beast::http::string_body> res_byte;
    boost::beast::http::read(stream, buffer, res_byte);
    LOG(INFO) << "Downloading bytecode.cvd...";

    std::ofstream bytecode_db(bytecode_file.append("/bytecode.cvd"),
                              std::ofstream::out | std::ofstream::binary);

    bytecode_db << res_byte.body();
    bytecode_db.close();

    // Download main.cvd
    boost::asio::connect(stream.next_layer(), results.begin(), results.end());
    stream.handshake(boost::asio::ssl::stream_base::client);

    req.target("/main.cvd");

    boost::beast::http::write(stream, req);
    boost::beast::http::response_parser<boost::beast::http::file_body> res_main;
    res_main.body_limit((std::numeric_limits<std::uint64_t>::max)());
    LOG(INFO) << "Downloading main.cvd...";

    res_main.get().body().open(main_file.append("/main.cvd").c_str(),
                               boost::beast::file_mode::write, ec);
    boost::beast::http::read(stream, buffer, res_main);

    // Download daily.cvd
    boost::asio::connect(stream.next_layer(), results.begin(), results.end());
    stream.handshake(boost::asio::ssl::stream_base::client);

    req.target("/daily.cvd");
    boost::beast::http::write(stream, req);
    boost::beast::http::response_parser<boost::beast::http::file_body>
        res_daily;
    res_daily.body_limit((std::numeric_limits<std::uint64_t>::max)());
    LOG(INFO) << "Downloading daily.cvd...";

    res_daily.get().body().open(daily_file.append("/daily.cvd").c_str(),
                                boost::beast::file_mode::write, ec);
    boost::beast::http::read(stream, buffer, res_daily);
    stream.shutdown(ec);
  }
}

int main(int argc, char *argv[]) {
  update_clamDBs();

  osquery::Initializer runner(argc, argv, osquery::ToolType::EXTENSION);
  auto status = osquery::startExtension("clamav", "0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
  }

  runner.waitForShutdown();
  return 0;
}
