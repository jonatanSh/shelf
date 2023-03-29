# Mitigations bypass

### RWX
In some operating system you can't allocate RWX memory.
To bypass this mitigation for Linux OS add the following:
```cmd
--mitigation-bypass rwx
```
#### How does this work ?
To bypass this mitigation we create a pre_relocate_write_hook and a pre_relocate_execute_hook
then change the memory permissions accordingly.
and finally create a pre_execute_shellcode_hook the change the permissions to RX.
The reason we use hooks instead of implementing this logic inside the loader
is because this project is intended to support large variety of operating systems
and if this logic was inside the mini loader the mini loader will be os dependent.

[Read more about the hooks](../shelf/hooks/builtin/rwx_bypass.py)
