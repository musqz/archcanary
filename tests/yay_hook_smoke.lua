-- Loads configs/yay-init.lua under gopher-lua (yay's Lua engine) with a stubbed
-- `yay` API and fires one AURPostDownload event. Run via tests/run_matching_tests.sh.
-- env: INIT (init.lua path), PKG, PKGBUILD_TEXT, WORKDIR
local handler
local logs, aborted = {}, nil
yay = {
  opt = {},
  log = {
    warn = function(m) logs[#logs + 1] = "warn: " .. m end,
    info = function(m) logs[#logs + 1] = "info: " .. m end,
  },
  abort = function(m) aborted = m; error("yay.abort", 0) end,
  create_autocmd = function(name, spec)
    if name == "AURPostDownload" then handler = spec.callback end
  end,
}

local ok, err = pcall(dofile, os.getenv("INIT"))
if not ok then print("status=load-crash " .. tostring(err)); os.exit(0) end

ok, err = pcall(handler, {
  match = os.getenv("PKG"),
  data = { pkgbuild = os.getenv("PKGBUILD_TEXT"), dir = os.getenv("WORKDIR") },
})
if aborted then
  print("status=abort " .. aborted)
elseif not ok then
  print("status=crash " .. tostring(err))
else
  print("status=ok")
end
for _, l in ipairs(logs) do print(l) end
