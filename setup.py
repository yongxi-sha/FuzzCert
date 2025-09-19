from setuptools import setup, find_packages


setup(
    name="FuzzCert",
    version="0.1.0",
    description="Fuzzing Framework for Certifiable Robustness of Neural Networks",
    author="Yongxi Sha",
    author_email="yongxi.sha@usu.edu",
    packages=find_packages(),
    install_requires=[
        # "numpy",
        # "onnx",
        # "tqdm",
    ],
    entry_points={
        "console_scripts": [
            "fuzzcert = fuzzcert.main:main",  # from fuzzcert/main.py
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)


