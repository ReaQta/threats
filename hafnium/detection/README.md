# HAFNIUM targeting Exchange Servers with 0-day exploits

ref: <https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/>

Compatible OS:

- Windows

Binding Events:

- Process Create
- Etw DNS (v2)

## Version 2

- Bind on Etw DNS
- Added check for suspicous dns event
- Added check on suspicious powershell process creation

## Version 1

- Binding on Process Created
- Initial implementation
