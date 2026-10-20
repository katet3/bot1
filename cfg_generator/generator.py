# cfg_generator/generator.py
from cfg_generator.builder import build_cfg

class CFGGenerator:
    def build(self, method):
        return build_cfg(method)