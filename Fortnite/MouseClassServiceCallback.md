# MouseClassServiceCallback
### EAC now hooks **ClassService** through:
``MouseDevice->DeviceExtension->MouhidDeviceObject->DeviceExtension->ConnectedData``.

EAC callback perform two checks (caller address & input buffer), but they are useless.

**ExtraInformation** is the trick!
Fortnite now only accept mouse input if **ExtraInformation** is set to a valid value.

That’s why EAC hooks the mouse callback: it sets the correct **ExtraInformation**, ensuring that legitimate mouse input is accepted by the game.

Solution:
Just add this to your input and make sure to call the callback directly like **Mouclass->MouseClassServiceCallback(...)**
```cpp
Input.ExtraInformation = Mouse::GetExtraInformation();
```

```cpp
uint32_t GetExtraInformation() {
    static uint32_t ExtraInformation = 0;

    if (!ExtraInformation) {
        auto EACBase = GetModuleBaseAddress(L"EasyAntiCheat_EOS.sys");
        if (EACBase) {
            auto DataSection = GetSectionByName(EACBase, ".data");
            if (DataSection.VirtualAddress && DataSection.Misc.VirtualSize) {
                auto FoundAddress = FindPattern(PVOID(uint64_t(EACBase) + DataSection.VirtualAddress), DataSection.Misc.VirtualSize,
                    "\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\x87", "xxxxxxxxxx?????????xx");

                if (FoundAddress) {
                    ExtraInformation = ~_rotr(~*(uint32_t*)(FoundAddress + 0xa), 23);
                }
            }
        }
    }

    return ExtraInformation;
}
```