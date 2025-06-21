import os
def load_config_from_corpus(corpus_dir):
    for filename in os.listdir(corpus_dir):
        path=os.path.join(corpus_dir,filename)
        fuzz_args=[
            f"--config_file={path}",
            "--output_dir=/src/out",
            "--halt_on_first=loose",
        ]
        break

    return fuzz_args
