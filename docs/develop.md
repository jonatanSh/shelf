# Key concepts
* The mini loader can't use functions (if functions are used the mini loader may contain relocations)

## Development features
* For development, it is advised to use the [eshelf output format](eshelf.md)
* you can specify the loader in the command line arguments and compile a debug loader


### Specify the loader
```bash
--loader-path <path_to_loader> --loader-symbols-path <path_to_loader_symbols>
```
