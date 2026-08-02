-- ~/.config/yay/init.lua
--
-- yay 13.0 Lua hooks for the AUR security stack (v2).
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

-- Static pattern check before build
yay.create_autocmd("AURPreInstall", {
  desc = "block known malicious PKGBUILD patterns",
  callback = function(event)
    local pkg      = event.match
    local pkgbuild = event.data.pkgbuild

    local patterns = {
      "npm install atomic%-lockfile",   -- Atomic Arch campaign wave 1
      "bun install js%-digest",         -- wave 2
      "curl[^\n]*|[^\n]*bash",
      "curl[^\n]*|[^\n]*sh",
      "wget[^\n]*|[^\n]*bash",
      "wget[^\n]*|[^\n]*sh",
    }

    for _, pattern in ipairs(patterns) do
      if pkgbuild:match(pattern) then
        yay.abort(pkg .. ": blocked — suspicious pattern: " .. pattern)
      end
    end
  end,
})

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

-- aur-audit.wtako.net black/red check (complements the pattern block above;
-- lists are synced by `archcanary --refresh`, already run weekly by
-- archcanary.timer — see docs/my-setup.md)
yay.create_autocmd("AURPreInstall", {
  desc = "aur-audit.wtako.net black/red check",
  callback = function(event)
    local dir = _archcanary_config_dir()
    local black = _archcanary_load_pkg_set(dir .. "/aur_audit_black.txt")
    local red   = _archcanary_load_pkg_set(dir .. "/aur_audit_red.txt")

    if black[event.match] then
      yay.abort(event.match .. ": aur-audit flagged BLACK (confirmed malicious) — https://aur-audit.wtako.net")
    elseif red[event.match] then
      yay.log.warn(event.match .. ": aur-audit flagged RED (high-risk, unconfirmed) — review before continuing")
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
