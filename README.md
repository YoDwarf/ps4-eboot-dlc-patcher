# ps4-eboot-dlc-patcher

This is intended to be used on ps5 where dlc fpkgs dont work. It automatically patches the eboot (or other executables) to use custom prx which replaces calls to the `libSceAppContent` and `libSceNpEntitlementAccess` library to load dlcs from the base pkg.

![showcase](https://github.com/idlesauce/ps4-eboot-dlc-patcher/assets/148508202/87d5fb21-f442-45b5-bba9-d4cff2e5de2d)

## Tools
- [selfutil-patched](https://github.com/xSpecialFoodx/SelfUtil-Patched) (Make sure you use this, as this is the only reliable version), if you have missing dlls cyb1k's fork should also work: [selfutil-patched](https://github.com/CyB1K/SelfUtil-Patched)
- For repacking and extracting the base/update either of the following:
    - [Modded Warfare's Patch Builder](https://www.mediafire.com/file/xw0zn2e0rjaf5k7/Patch_Builder_v1.3.3.zip/file) <- this is the easiest to use
    - [PS4-Fake-PKG-Tools-3.87](https://github.com/CyB1K/PS4-Fake-PKG-Tools-3.87)
    - [PkgEditor or PkgTool](https://github.com/maxton/LibOrbisPkg/releases/latest), which is able to extract fake pkgs with a custom passcode, and the cli version runs cross-platform however it can only build base packages.

## Download
- [Windows 64-bit](https://github.com/idlesauce/ps4-eboot-dlc-patcher/releases/latest/download/ps4-eboot-dlc-patcher-win-x64.exe)

Other os and arch binaries are available [here](https://github.com/idlesauce/ps4-eboot-dlc-patcher/releases/latest). 

Releases with os and architecture tags are compiled with native AOT, so they dont require any dependencies other than an ansi compatible terminal, which is default on windows 10 and above, if you happen to use an older windows version [conemu](https://conemu.github.io/) works.

There is also a `framework-dependent` release which is cross-platform, but requires the dotnet 8 runtime, you can run it like this: `dotnet ps4-eboot-dlc-patcher.dll <args>`
  
## Instructions
Video tutorial by Modded Warfare: [https://www.youtube.com/watch?v=xWu-a7Im3V8](https://www.youtube.com/watch?v=xWu-a7Im3V8)

*The following instructions are for Patch Builder, using the other options may require additional steps, like modifying the param.sfo and resigning the executables manually, PkgEditor uses uroot instead of Image0.*
1. Extract the update pkg of the game, or if the game is base only or merged base+update, then extract the `Sc0` and `sce_sys` folders along with the executables to patch. The executables you need will most likely be `eboot.bin` and other `.elf` files (most games only use the `eboot.bin`) (it could also be `.prx`, but ignore `.prx` files in the `sce_module` folder)
1. Run selfutil on the executables to unsign them.
1. For the easiest usage copy all the dlc pkgs and executables into a folder then highlight and drag them onto the `ps4-eboot-dlc-patcher` exe. (You can also drag just the dlc pkgs onto it and enter the executables paths in the menu, or enter all paths as cli arguments)
1. Select patch executable(s) and wait for the patcher to do its thing
1. After its done it'll ask you if you want to list the corresponding folder names for each dlc to copy the data into, or automatically extract dlc data. Choose automatic and enter the path to the extracted update's Image0 directory.
1. The patcher outputs the patched executables in the same folder as the patcher exe/eboot_patcher_output, copy back the executables into the update folder. Make sure you rename the file back to what it was before you ran selfutil since it changes the extension to .elf! The `dlcldr.prx` always goes into the root of Image0 of the update, even if the executables to patch werent in that folder.
1. Repack the update

## Limitations
- Only functions that are in fw 9.xx are fully supported, so games backported to that version or older work. As far as i can tell as of now (latest is ps4 11.xx) there was only one new function added to the related libraries (`sceNpEntitlementAccessGetGameTrialsFlag`), i added this to the prx to avoid a certain crash if the game calls this however its not properly implemented, so games up to 11.xx may or may not work.
- 99+% of games should work with the prx method, but theres a fallback to in executable handlers, however this only handles up to 99 dlcs, and doesnt support entitlement keys or entitlement access, for these scenarios the patcher will give a heads up.
- I have encountered one game (Shadow of the Tomb Raider) that only accepts root directory mount points for dlcs, so the dlcXX subdirectory my patcher uses did not work (tested the mountpoint as /data which worked). Thankfully this game already checks for the dlc data in app0 so you can just copy the dlc files into the update and not even need patches with this app. I tested the mountpoint as /data/dlc00 with data both in that folder and in /data, and it didnt work, which means the game doesnt just strip the subdirectory, it completely disregards the mountpoint, not trusting what the "system" returns is unusual for a game to do, so this game is an exception, this shouldnt be a widespread issue.

## Notes
- You cannot create update pkgs for remaster type pkgs, if the pub tools detect that the param.sfo contains a `REMASTER_TYPE` field, it'll fail, thankfully these pkgs are very rare, and if you encounter them you can edit the sfo and repack the base.
- If you are creating the dlcXX folders manually, keep in mind there are two types of dlcs, `With Extra Data`, and `Without extra data`. This is the pkg type, it doesnt not necessarily mean that the dlc has files, but this type is passed to the game, and the game might choose call mount on all dlcs marked as with extra data, check for files in the folders, this would fail if you didnt create an empty folder, so to avoid potentially unexpected behaviour create these folders even for dlcs that dont have any files.

## Credits and thanks
- The biggest thanks to [jocover](https://github.com/jocover) who came up with the idea, without whom i never would've learned this was possible.
- The [OpenOrbis team](https://github.com/OpenOrbis) for creating [the tools that were used to compile the prx](https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain).
- [SocraticBliss](https://github.com/SocraticBliss) for creating [ps4_module_loader](https://github.com/SocraticBliss/ps4_module_loader/).
- [maxton](https://github.com/maxton) for creating [LibOrbisPkg](https://github.com/OpenOrbis/LibOrbisPkg) and the [OpenOrbis team](https://github.com/OpenOrbis) for maintaining it.
- [Iced](https://github.com/icedland/iced)
- [spectre.console](https://github.com/spectreconsole/spectre.console)
- Big shoutout to [hrdcrd](https://twitter.com/hrdcrd) for testing a ton of games and reporting bugs!
