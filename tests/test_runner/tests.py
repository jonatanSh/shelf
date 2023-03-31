from test_runner.consts import Arches, TestFeatures
import itertools

all_arches = [arch.value for arch in Arches]


def bind_together(*features_to_bind):
    bounded = []
    for bounded_f in itertools.permutations(features_to_bind):
        bounded_f = list(bounded_f)
        bounded.append(bounded_f)
    return bounded


def forbidden_features(*maps):
    bounded = []
    for feature_map in maps:
        bounded += feature_map

    return bounded


TESTS = {
    'elf_features': {
        "test_file_fmt": "../outputs/{}_elf_features.out{}.shellcode",
        "supported_arches": all_arches,
        "success": ["__Test_output_Success"],
        "features": [TestFeatures.ESHELF,
                     TestFeatures.DYNAMIC,
                     TestFeatures.NORWX],
        "disabled_features": forbidden_features(
            bind_together(TestFeatures.ESHELF, TestFeatures.DYNAMIC),
            bind_together(TestFeatures.ESHELF, TestFeatures.DYNAMIC, TestFeatures.NORWX),
        )
    },
    'no_relocations': {
        "test_file_fmt": "../outputs/no_libc_{}_no_relocations.out.shellcode",
        "supported_arches": [Arches.intel_x32.value, Arches.aarch64.value],
        "success": ["Hello"],
        "features": []
    },
    'hooks': {
        "test_file_fmt": "../outputs/{}_elf_features.out.hooks.shellcode",
        "success": ['Hello',
                    "Hello from startup hook!",
                    "Hello from pre write hook!",
                    "Hello from pre call main hook!",
                    "__Test_output_Success"],
        "supported_arches": all_arches,
        "features": [],
    },

}


def get_test_with_features(test_name):
    test_features = []
    for feature in TestFeatures:
        test_name_after = test_name.replace("{}_".format(feature.value), "")
        if test_name_after != test_name:
            test_features.append(feature)
        test_name = test_name_after
    return test_name, test_features


TEST_CASES = []

for test, params in TESTS.items():
    TEST_CASES.append(test)
    features = [f.value for f in params["features"]]
    for i in range(len(features)):
        for c in itertools.combinations(features, i + 1):
            if c:
                TEST_CASES.append("{}_{}".format("_".join(c), test))
