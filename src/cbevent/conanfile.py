from conans import ConanFile, CMake

class cbeventConan(ConanFile):
    name = "cbevent"
    version = "0.6"
    license = "BSD-2-Clause"
    url = "https://gitlab.bit9.local/dheater/cbevent"
    description = "CB Event structure shared between CBR linux event generators and the daemon"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False]}
    default_options = {"shared": False}
    generators = "cmake"
    exports_sources = "src/*"
    build_requires = "nlohmann_json/3.8.0"

    def build(self):
        cmake = CMake(self)
        cmake.configure(source_folder="src")
        cmake.build()

    def package(self):
        self.copy("src/*.h", dst="include", keep_path=False)
        self.copy("lib/*.a", dst="lib", keep_path=False)


    def package_info(self):
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.libdirs = ["lib"]
        self.cpp_info.libs = ["cbevent_json"]
