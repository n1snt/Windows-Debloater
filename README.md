# Windows Decrapifier
A simple powershell script to debloat Windows.

### How to Use:
1. Download/clone this repo.
2. Right Click on start button & open Powershell(Admin)
3. This step depends on where you have downloaded the script.
    We will assume that you have downloaded this scipt in downloads.
    ```
    cd ..
    cd C:\Users\<Your Windows username>\Downloads\
    cd .\Windows-Decrapifier-main\Windows-Decrapifier-main\
    ```
4. Type the following commands :
    ```
    Set-ExecutionPolicy Unrestricted
    ```
    ```
    .\decrapify.ps1
    ```
*Note : Make sure to enable/disable the features you don't need by commenting/uncommenting them out.*

### What this script can do :
1. Enable/Disable Telemetry
2. Enable/Disable Wi-Fi Sense
3. Enable/Disable SmartScreen Filter
4. Enable/Disable Bing Search in Start Menu
5. Enable/Disable Location Tracking
6. Enable/Disable Feedback
7. Enable/Disable Advertising ID
8. Enable/Disable Cortana
9. Restrict Windows Update P2P only to local network
10. Remove AutoLogger file & restrict directory
11. Stop & disable Diagnostics Tracking Service
12. Lower/Raise UAC level
13. Enable/Disable sharing mapped drives between users
14. Enable/Disable Firewall
15. Enable/Disable Windows Defender
16. Enable/Disable Windows Update automatic restart
17. Stop & disable Home Groups services
18. Enable/Disable Remote Assistance
19. Enable/Disable Remote Desktop w/o Network Level Authentication
20. Enable/Disable Action Center
21. Enable/Disable Lock screen
22. Enable/Disable Autoplay
23. Enable/Disable Autorun for all drives
24. Enable/Disable Sticky keys prompt
25. Hide/Show Search button / box
26. Hide/Show Task View button
27. Hide/Show small/large icons in taskbar
28. Hide/Show titles in taskbar
29. Hide/Show all tray icons
30. Hide/Show known file extensions
31. Change default Explorer view to "Computer"/"Quick Access"
32. Hide/Show Computer shortcut on desktop
33. Remove Desktop icon from computer namespace
34. Remove Documents icon from computer namespace
35. Remove Downloads icon from computer namespace
36. Remove Downloads icon to computer namespace
37. Remove Music icon from computer namespace
38. Remove Pictures icon from computer namespace
39. Remove Videos icon from computer namespace
40. Remove secondary en-US keyboard
41. Enable/Disable/Uninstall OneDrive
42. Install/Uninstall default Microsoft applications
43. Uninstall Work Folders Client
44. Enable/Disable unwanted Windows services
45. Enable/Disable many of the default apps.
46. Prevents Apps from re-installing
47. Remove/Set Password Age Limit
48. Enable/Disable Privacy Settings Experience
49. Sets Windows to Dark Mode

### Defaults:
By default this script has options enabled for a normal user.
1. Telemetry is disabled.
2. Wi-Fi sense is disabled.
3. SmartScreen Filter is disabled.
4. Bing Search diabled in Start Menu.
5. Location Tracking is disabled.
6. Feedback is disabled.
7. Advertising ID is disabled.
8. Cortana is disabled.
9. Restricted Windows Update P2P only to local network.
10. Removed AutoLogger file and restrict directory.
11. Stopped and disabled Diagnostics Tracking Service.
12. Disabled Windows Update automatic restart.
13. Stoped and disabled Home Groups services.
14. Show known file extensions.
15. Change default Explorer view to "Computer"
16. Disabled OneDrive.
17. It removes some of the bloatware bundled with Windows 10 :
    1. 3DBuilder
    2. BingFinance
    3. BingNews
    4. BingSports
    5. BingWeather
    6. Getstarted
    7. People
    8. SkypeApp
    9. WindowsMaps
    10. WindowsPhone
    11. WindowsSoundRecorder
    12. AppConnector
    13. Messaging
    14. CommsPhone
    15. CandyCrushSodaSaga
    16. WindowsFeedbackHub
    17. Wallet
    18. GetHelp
    19. MixedReality
    20. Everything Office related.
    21. Everything Xbox related.
    22. WindowsCamera
18. Disables all settings in Privacy Experience.
19. Disable Remote Assistance
20. Disable Remote Desktop

#### Credits :
[@Disassembler0]( https://github.com/Disassembler0 ).
[Craft Computing]( https://www.youtube.com/channel/UCp3yVOm6A55nx65STpm3tXQ ).
Windows Debloat Video URL : https://www.youtube.com/watch?v=PdKMiFKGQuc <br>
