# fuzzing_VERAPAK
fuzzer/  
│  
├── fuzz_target.py             # entrypoint (runs atheris)  
├── config_loader.py         # config/sets loading  
├── region_utils.py            # region, area serialization/deserialization  
├── mutator.py                 # custom mutator logic  
├── corpus/                      # fuzzing corpus  
└── VERAPAK                   # VERAPAK source code  
