local icehst = require("icehst")

local mon = peripheral.find("monitor")
mon.setTextScale(0.5)

-- data : table
-- sender : int (id of the computer that sent the request)
icehst.route("/main/sendcode", function(sender, data)
    return 200 -- sends {}, 200
end)

icehst.route("/main/sendstr", function(sender, data)
    return "Hello, world!" -- sends {0: "Hello, world!"}, 200
end)

icehst.route("/main/sendjson", function(sender, data)
    return {
        message = "Hello, world!"
    } -- sends {message: "Hello, world!"}, 200
end)

icehst.route("/main/sendjsonandcode", function(sender, data)
    return {
        message = "Hello, world!"
    }, 300 -- sends {message: "Hello, world!"}, 300
end)

icehst.route("/main/sendstrandcode", function(sender, data)
    return "Hello, world!", 300 -- sends {0: "Hello, world!"}, 300
end)

local config = {
    display = mon,
    fmt = { -- all fmts are %day %mon %year %hr %min %sec %level %route %senderid %datasent %datarecv %jsonsent %jsonrecv %code
        log = "[%day-%mon-%year %hr:%min] ", -- base fmt
        request = "%route %code",      -- added on the base        
    },
    modem = peripheral.find("modem"),
    encrypted = true
}

icehst.run("demo", config)
