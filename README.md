# cc.icehst

A Computer Craft tweaked ```Lua``` lib which is a server to client encrypted data transfer lib with its own protcall, via rednet

A list of features it has

- Async Routes
- Automatic registry with ```rednet.lookup```
- Server to Client encryption with AES-CTR encryption using a 16-byte derived session key and random IV
- Status Codes
- Retargetable logger (can log to diffrent monitors or terms)
- Loging formats
- Its own ```.request(url, data, timeout=5sec)``` function

**NOTE**: _It does not have get, post, delete or any other method_

_An example of icehst being used in my survival world. The Advanced computer is running a server script and a Normal pocket computer is running a client script_
<img width="959" height="503" alt="image" src="https://github.com/user-attachments/assets/a6a9e9bc-ea46-4c0a-95de-448badc54810" />

A brief overview of its API

```lua
icehst.run(
  sitename : string  -- site name to register to
  config   : table   -- config for the server
)

config : table = {
  display : term api interface
  fmt : table = {
    log : string      -- base logging fmt          "[%day-%mon-%year %hr:%min] "
    request : string  -- added on top of the base  "%route %code" 
  }
-- all possible fmt are %day      %mon   %year     %hr       %min      %sec
--                          %level    %route %senderid %datasent %datarecv %jsonsent
--                          %jsonrecv %code
  encrypted : bool | nil = true
  modem : modem peripheral object
  side  : string | nil = side where a modem exists
}

icehst.route(
  path : string
  callback : function(number, table) -> table{table{}, number}, table, number, table{string, number}, string
)

icehst.request(
  url : string
  data : table
  timeout : number | nil = 5seconds
)
```
