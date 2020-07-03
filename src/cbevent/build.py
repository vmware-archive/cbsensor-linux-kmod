from cpt.packager import ConanMultiPackager

if __name__ == "__main__":
    builder = ConanMultiPackager()
    builder.add(settings={"arch": "x86_64", "build_type": "Release"},
                options={}, env_vars={}, build_requires={})
    builder.add(settings={"arch": "x86_64", "build_type": "Debug"},
                options={}, env_vars={}, build_requires={})
    builder.add(settings={"arch": "armv6", "build_type": "Release"},
                options={}, env_vars={}, build_requires={})
    builder.run()
