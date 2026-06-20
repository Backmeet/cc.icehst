local icehst = require("icehst")
printp = require("cc.pretty").pretty_print

while 1 do
    --    int, table
    local code, data = icehst.request("demo/main/sendjson", {}, 5)
    print("status:", code)
    term.write("response:")
    printp(data)
    sleep(0.5)
end
