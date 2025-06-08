import yaml

def load_dpdk_yaml():

    #TODO for temporarly hardcoding the YAML config path, for later on it will be standridzed
    # into global configs and will be automatically generated or can be access via a global
    # directory variable
    config_path = "/home/yigit/workspace/github/dpdk-pot/make/dpkd-pot.yaml"

    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
        return config
