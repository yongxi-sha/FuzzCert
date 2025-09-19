from abc import ABC, abstractmethod
import numpy as np
from typing import Any, Union

class FunctionAdapter (ABC):
    """
    Abstract base class for integrating different neural network verification tools
    with FuzzCert. Each benchmark-specific adapter must inherit from this class and
    implement all abstract methods.
    """

    def __init__(self, config: Any, function_name, benchmark_name="verapak"):
        """
        Initialize the adapter with a parsed configuration object.

        Args:
            config (Any): Configuration object containing CLI or config file parameters.
        """
        self.config = config
        self.function_name = function_name
        self.benchmark_name = benchmark_name

    @abstractmethod
    def initialize(self) -> None:
        """
        Load model, spec files, or perform any other setup logic specific to the benchmark.
        This is called once before fuzzing starts.
        """
        pass

    @abstractmethod
    def my_mutate(self, base_input: np.ndarray) -> np.ndarray:
        """
        Generate a mutated input based on the given base input.

        Args:
            base_input (np.ndarray): Original input around which to apply mutation.

        Returns:
            np.ndarray: Mutated input array.
        """
        pass

    @abstractmethod
    def serialize(self, data: np.ndarray, input_dtype: Union[type, str]) -> bytes:
        """
        Serialize an input (e.g., float array) into bytes for Atheris fuzzing.

        Args:
            data (np.ndarray): Input data to serialize.
            input_dtype (Union[type, str]): Data type for serialization (e.g., np.float32).

        Returns:
            bytes: Serialized byte stream representing the input.
        """
        pass

    @abstractmethod
    def deserialize(self, data: bytes, input_dtype: Union[type, str]) -> np.ndarray:
        """
        Deserialize a byte stream back into an input array.

        Args:
            data (bytes): Input byte stream from Atheris.
            input_dtype (Union[type, str]): Target data type to convert the bytes to.

        Returns:
            np.ndarray: Reconstructed input array from bytes.
        """
        pass
    
    @abstractmethod
    def strip_fuzzcert_args(self, argv):
        """
        clean argv

        Returns:
            str: cleaned argv.
        """
        pass

    @abstractmethod
    def falsify_predicate(self,pre_size: dict, post_size: dict) -> bool:
        """
        compare pre_set and post_set

        Returns:
            bool: true or false
        """
        pass

    @abstractmethod
    def testoneinput(self, region):
        """
        fuzzing logic for VERAPAK falsify

        Returns:
            None
        """
        pass


class BenchAdapter(ABC):
    """
    Abstract base class for integrating different neural network verification tools
    with FuzzCert. Each benchmark-specific adapter must inherit from this class and
    implement all abstract methods.
    """

    def __init__(self, config: Any, function_name, benchmark_name="verapak"):
        """
        Initialize the adapter with a parsed configuration object.

        Args:
            config (Any): Configuration object containing CLI or config file parameters.
        """
        self.config = config
        self.function_name = function_name
        self.benchmark_name = benchmark_name

    @abstractmethod
    def initialize(self) -> None:
        """
        Load model, spec files, or perform any other setup logic specific to the benchmark.
        This is called once before fuzzing starts.
        """
        pass

    @abstractmethod
    def my_mutate(self, base_input: np.ndarray) -> np.ndarray:
        """
        Generate a mutated input based on the given base input.

        Args:
            base_input (np.ndarray): Original input around which to apply mutation.

        Returns:
            np.ndarray: Mutated input array.
        """
        pass

    @abstractmethod
    def serialize(self, data: np.ndarray, input_dtype: Union[type, str]) -> bytes:
        """
        Serialize an input (e.g., float array) into bytes for Atheris fuzzing.

        Args:
            data (np.ndarray): Input data to serialize.
            input_dtype (Union[type, str]): Data type for serialization (e.g., np.float32).

        Returns:
            bytes: Serialized byte stream representing the input.
        """
        pass

    @abstractmethod
    def deserialize(self, data: bytes, input_dtype: Union[type, str]) -> np.ndarray:
        """
        Deserialize a byte stream back into an input array.

        Args:
            data (bytes): Input byte stream from Atheris.
            input_dtype (Union[type, str]): Target data type to convert the bytes to.

        Returns:
            np.ndarray: Reconstructed input array from bytes.
        """
        pass
    
    @abstractmethod
    def strip_fuzzcert_args(self, argv):
        """
        clean argv

        Returns:
            str: cleaned argv.
        """
        pass

    @abstractmethod
    def falsify_predicate(self,pre_size: dict, post_size: dict) -> bool:
        """
        compare pre_set and post_set

        Returns:
            bool: true or false
        """
        pass

    @abstractmethod
    def testoneinput(self, region):
        """
        fuzzing logic for VERAPAK falsify

        Returns:
            None
        """
        pass

