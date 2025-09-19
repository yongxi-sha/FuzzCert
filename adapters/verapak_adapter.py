from fuzzcert.bench_adapter import BenchAdapter

class VerapakAdapter(BenchAdapter):

    def __init__(self, config, function_name, benchmark_name="verapak"):
        super().__init__(config, function_name=function_name)
        # 延迟在 register_fadapter 中导入具体的 function adapter class
        self.register_fadapter()
        self.function_name = function_name
        # 获取 function adapter class（不一定要立即实例化——根据需要）
        FadapterClass = self.get_fadapter(function_name)
        if FadapterClass is None:
            raise ValueError(f"No function adapter registered for '{function_name}'")
        # 这里创建函数级适配器实例（传入必要参数：config, function_name, benchmark_name）
        self.function_adapter = FadapterClass(config, function_name, benchmark_name=benchmark_name)

    def get_fadapter(self, function_name):
        """返回注册表中对应的函数级 Adapter 类（或 None）"""
        return self.fadapters.get(function_name)

    def register_fadapter(self):
        # 局部导入以避免循环导入
        from falsify_adapter import FalsifyAdapter
        self.fadapters = {
            # Add function name -> AdapterClass mapping here
            "falsify": FalsifyAdapter,
        }

    def initialize(self, input_dir=None):
        """
        Initialize model configuration, region, and area info.
        """
        if hasattr(self.function_adapter, "initialize"):
            self.function_adapter.initialize(input_dir=input_dir)
    
    def strip_fuzzcert_args(self, argv):
        """Remove fuzzcert-specific args that Atheris doesn't understand"""
        return self.function_adapter.strip_fuzzcert_args(argv)

    def serialize(self, data) -> bytes:
        """
        Serialize a region and area into bytes (for corpus writing).

        Args:
            data: A tuple of (region, area), where region is (low, high, ()) and area is float.
            input_dtype: Data type of the region tensors (e.g., np.float32).

        Returns:
            bytes: Pickled representation of region+area.
        """
        return self.function_adapter.serialize(data)
    
    def deserialize(self, data):
        """
        Deserialize bytes into a region and area.

        Args:
            data (bytes): Serialized region/area data.
            input_dtype (type): Expected dtype (e.g., np.float32).

        Returns:
            Tuple: (region, area), where region = (low, high, ()), area is float.
        """
        
        return self.function_adapter.deserialize(data)
    
    def falsify_predicate(self, pre_size: dict, post_size: dict) -> bool:
        """
        :param pre_size: The size of each set prior to falsify call
        :param post_size: The size of each set after call to falsify
        :return: bool: Checks correctness and returns True/False
        """
        return self.function_adapter.falsify_predicate(pre_size,post_size)
        
    # ---------- fuzzing-facing API (pure delegation) ----------
    def my_mutator(self, data: bytes, max_size: int, seed: int) -> bytes:
        """
        Delegate to function-level adapter. Utility funcs stay in the function adapter.
        """
        return self.function_adapter.my_mutator(data, max_size, seed)

    def testoneinput(self, region) -> None:
        """
        Delegate to function-level adapter. All coverage/reporting logic stays there.
        """
        return self.function_adapter.testoneinput(region)
