from setuptools import setup, find_packages

setup(
    name="FuzzCert",
    version="0.1.0",
    description="Fuzzing Framework for Certifiable Robustness of Neural Networks",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(where="fuzzcert"),
    package_dir={"": "fuzzcert"},
    install_requires=[
        "numpy",
        "onnx",
        "tqdm",
    ],
    entry_points={
        "console_scripts": [
            "fuzzcert = main:main",  # from fuzzcert/main.py
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)


