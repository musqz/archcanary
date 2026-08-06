-- ~/.config/yay/init.lua
--
-- yay 13.0 Lua hooks for the AUR security stack (v7).
-- Seeded to ~/.config/yay/init.lua by install.sh if not already present.
-- An offline backstop that runs on every AUR install/upgrade: warns on
-- recently-modified PKGBUILDs and blocks known malicious patterns before
-- build. See docs/my-setup.md, "yay 13.0 integration".
--
-- Version marker above (the "(vN)" suffix) is checked by `--doctor` to
-- detect a stale local copy, since install.sh never overwrites an existing
-- init.lua. Bump it whenever the hooks below change; never touch the text
-- before "(vN)", since --doctor also prefix-matches on that stable part to
-- tell "some archcanary version present" from "never installed".

-- Options
yay.opt.diff_menu   = true
yay.opt.edit_menu   = true    -- lets you review each PKGBUILD before it builds
yay.opt.clean_menu  = true
yay.opt.clean_after = false
yay.opt.sort_by     = "votes"
yay.opt.bottom_up   = false

-- Warn about AUR packages with PKGBUILD modified < 3 days ago
yay.create_autocmd("UpgradeSelect", {
  desc = "flag recently modified AUR upgrades",
  callback = function(event)
    local cutoff = os.time() - (3 * 24 * 60 * 60)
    for _, pkg in ipairs(event.data.upgrades) do
      if pkg.repository == "aur" and pkg.last_modified >= cutoff then
        local hours = math.floor((os.time() - pkg.last_modified) / 3600)
        yay.log.warn(pkg.name .. ": PKGBUILD modified "
                     .. hours .. "h ago — review carefully")
      end
    end
    return { exclude = {}, skip_menu = false }
  end,
})

-- Pattern port (check_pkgbuild_caches, archcanary.sh): ANSI-C hex/octal
-- quoting with 3+ chained \xHH/\NNN escapes spelling out a command
-- byte-by-byte, e.g. $'\x63\x75\x72\x6c' for "curl". Lua patterns have no
-- counted repetition ({3,}) so this walks the string by hand, counting
-- consecutive escapes immediately after each literal "$'". A single escape
-- (read -d $'\0', the standard find -print0 idiom) must NOT match — this is
-- the same false positive check_pkgbuild_caches' own re_ansi_c already
-- fixed once (see its comment in archcanary.sh); do not reintroduce it here.
local function _archcanary_has_chained_ansi_c(pkgbuild)
  local pos = 1
  while true do
    local s, e = pkgbuild:find("$'", pos, true)
    if not s then return false end
    local i, run = e + 1, 0
    while true do
      local hx = pkgbuild:match("^\\x%x%x", i)
      local oc = (not hx) and pkgbuild:match("^\\[0-7][0-7]?[0-7]?", i)
      local esc = hx or oc
      if not esc then break end
      run = run + 1
      if run >= 3 then return true end
      i = i + #esc
    end
    pos = e + 1
  end
end

-- Pattern port: rev/tr piped to a shell — two independent per-line
-- substring checks ANDed together (order-independent, matching
-- check_pkgbuild_caches exactly). Lua has no alternation, so each side is a
-- small set of flat find() calls.
local function _archcanary_has_revtr_pipe_shell(pkgbuild)
  for line in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    local has_revtr = line:find("|%s*rev%s") or line:find("|%s*tr%s")
    local has_shell = line:find("|%s*bash") or line:find("|%s*sh") or line:find("|%s*eval")
    if has_revtr and has_shell then return true end
  end
  return false
end

local function _archcanary_config_dir()
  local xdg = os.getenv("XDG_CONFIG_HOME")
  if xdg and xdg ~= "" then return xdg .. "/archcanary" end
  return os.getenv("HOME") .. "/.config/archcanary"
end

local function _archcanary_load_pkg_set(path)
  local set = {}
  local f = io.open(path, "r")
  if not f then return set end
  for line in f:lines() do
    if not line:match("^#") and line:match("%S") then
      set[line] = true
    end
  end
  f:close()
  return set
end

-- Same "pkgname value" companion-file shape as aur_audit_red_dates.txt and
-- aur_audit_red_versions.txt -> name-to-value map. One loader for both, since
-- the format is identical.
local function _archcanary_load_pkg_map(path)
  local map = {}
  local f = io.open(path, "r")
  if not f then return map end
  for line in f:lines() do
    if not line:match("^#") and line:match("%S") then
      local name, value = line:match("^(%S+)%s+(%S+)")
      if name and value then map[name] = value end
    end
  end
  f:close()
  return map
end

-- Extracts "pkgver-pkgrel" from the freshly-downloaded PKGBUILD's raw text,
-- matching wtako's "version" field format (e.g. "0.5.8-2"), entirely offline
-- via string.match. Returns nil -- not a best-effort guess -- for anything
-- that isn't a simple static literal assignment: a pkgver() function
-- (VCS/-git packages compute this dynamically at build time, so a static
-- pkgver= line, if present at all, is just a stale placeholder), a
-- pkgver=/pkgrel= line that itself uses command or variable substitution
-- (e.g. pkgver=$(date +%Y%m%d), pkgver=${_ver} -- not a literal value, and
-- $(...)/${...} would otherwise leak into the captured string verbatim), or
-- a missing/unparseable line. Callers must treat nil as "unknown" and fall
-- back to the unconditional warning -- never fail open.
local function _archcanary_pkgbuild_version(pkgbuild)
  local pkgver, pkgrel, dynamic
  for line in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    if line:match("^%s*pkgver%s*%(%s*%)") then
      dynamic = true
    elseif not pkgver and line:match("^pkgver=") then
      if line:find("$", 1, true) then
        dynamic = true
      else
        pkgver = line:match("^pkgver=['\"]([^'\"]+)['\"]") or line:match("^pkgver=(%S+)")
      end
    end
    if not pkgrel and line:match("^pkgrel=") then
      if line:find("$", 1, true) then
        dynamic = true
      else
        pkgrel = line:match("^pkgrel=['\"]([^'\"]+)['\"]") or line:match("^pkgrel=(%S+)")
      end
    end
  end
  if dynamic or not pkgver or not pkgrel then return nil end
  return pkgver .. "-" .. pkgrel
end

-- Static pattern check + aur-audit.wtako.net black/red check, combined into
-- one hook (rather than two separate AURPostDownload registrations) so
-- there's a single "clean" confirmation line when nothing is found. Silence
-- alone can't be told apart from "hook never ran"; an explicit clean line
-- can. aur-audit lists are synced by `archcanary --refresh`, already run
-- weekly by archcanary.timer — see docs/my-setup.md.
--
-- AURPostDownload, not AURPreInstall: fires after yay's diff/edit/clean
-- review menus and makepkg --verifysource, so it scans the PKGBUILD as
-- reviewed/edited rather than a stale pre-review copy — still before
-- compatibility checks, PGP prompts, build, and install.
yay.create_autocmd("AURPostDownload", {
  desc = "block known malicious PKGBUILD patterns + aur-audit black/red check",
  callback = function(event)
    local pkg      = event.match
    local pkgbuild = event.data.pkgbuild
    local flagged  = false

    local patterns = {
      "npm install atomic%-lockfile",   -- Atomic Arch campaign wave 1
      "bun install js%-digest",         -- wave 2
      "curl[^\n]*|[^\n]*bash",
      "curl[^\n]*|[^\n]*sh",
      "wget[^\n]*|[^\n]*bash",
      "wget[^\n]*|[^\n]*sh",

      -- eval + command substitution
      "eval%s+%$%(",
      "eval%s+`",

      -- printf hex/octal obfuscation
      "printf[^\n]*\\x",
      "printf[^\n]*\\0",

      -- variable-split command reassembly (a=bu; b=n; $a$b)
      "[%l_]+=%a+;%s*[%l_]+=%a+;%s*%$",

      -- base64 decode piped to shell — no alternation in Lua patterns, so
      -- flag/target combos are flattened, same as the curl/wget entries above
      "base64[^\n]*%-%-decode[^\n]*|[^\n]*bash",
      "base64[^\n]*%-%-decode[^\n]*|[^\n]*sh",
      "base64[^\n]*%-%-decode[^\n]*|[^\n]*eval",
      "base64[^\n]*%-d[^\n]*|[^\n]*bash",
      "base64[^\n]*%-d[^\n]*|[^\n]*sh",
      "base64[^\n]*%-d[^\n]*|[^\n]*eval",
    }

    for _, pattern in ipairs(patterns) do
      if pkgbuild:match(pattern) then
        flagged = true
        yay.abort("ARCHCANARY: " .. pkg .. " — BLOCKED: SUSPICIOUS PATTERN! (" .. pattern .. ")")
      end
    end

    if _archcanary_has_chained_ansi_c(pkgbuild) then
      flagged = true
      yay.abort("ARCHCANARY: " .. pkg .. " — BLOCKED: SUSPICIOUS PATTERN! (ANSI-C chained hex/octal escapes)")
    end
    if _archcanary_has_revtr_pipe_shell(pkgbuild) then
      flagged = true
      yay.abort("ARCHCANARY: " .. pkg .. " — BLOCKED: SUSPICIOUS PATTERN! (rev/tr piped to shell)")
    end

    local dir          = _archcanary_config_dir()
    local black        = _archcanary_load_pkg_set(dir .. "/aur_audit_black.txt")
    local red          = _archcanary_load_pkg_set(dir .. "/aur_audit_red.txt")
    local red_versions = _archcanary_load_pkg_map(dir .. "/aur_audit_red_versions.txt")
    local red_dates    = _archcanary_load_pkg_map(dir .. "/aur_audit_red_dates.txt")

    if black[pkg] then
      flagged = true
      yay.abort("ARCHCANARY: " .. pkg .. " — AUR-AUDIT FLAGGED BLACK (CONFIRMED MALICIOUS)! — https://aur-audit.wtako.net")
    elseif red[pkg] then
      flagged = true
      -- A name-only match would otherwise warn forever, even once a newer
      -- version is rescanned clean (e.g. firefox-pure: flagged red on an old
      -- version, current version already clean on wtako's own site). Exact
      -- version-string match, not vercmp ordering -- deliberately simple.
      -- Any missing piece (versions file not yet refreshed, dynamic
      -- pkgver(), unparseable PKGBUILD) falls through to the original
      -- unconditional wording below.
      local flagged_ver = red_versions[pkg]
      local current_ver = _archcanary_pkgbuild_version(pkgbuild)
      if flagged_ver and current_ver and current_ver ~= flagged_ver then
        local flagged_date = red_dates[pkg]
        local ver_info = flagged_ver .. (flagged_date and (", " .. flagged_date) or "")
        yay.log.warn("ARCHCANARY: " .. pkg .. " — AUR-AUDIT FLAGGED RED FOR A DIFFERENT VERSION! (" .. ver_info
                     .. ") — installing " .. current_ver
                     .. " — verify at aur-audit.wtako.net if this looks stale")
      else
        yay.log.warn("ARCHCANARY: " .. pkg .. " — AUR-AUDIT FLAGGED RED (HIGH-RISK, UNCONFIRMED)! — review before continuing")
      end
    end

    if not flagged then
      yay.log.info("ARCHCANARY: " .. pkg .. " — PKGBUILD CHECKS CLEAN!")
    end
  end,
})

-- Log AUR installs
yay.create_autocmd("PostInstall", {
  desc = "log AUR installs",
  callback = function(event)
    for _, pkg in ipairs(event.data.packages) do
      if pkg.source == "aur" then
        yay.log.info("AUR installed: " .. pkg.name .. " " .. pkg.version)
      end
    end
  end,
})
