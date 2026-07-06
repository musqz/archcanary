-- ~/.config/yay/init.lua
--
-- yay 13.0 Lua hooks for the AUR security stack.
-- Seeded to ~/.config/yay/init.lua by install.sh if not already present.
-- An offline backstop that runs on every AUR install/upgrade alongside the
-- aurscan editor-gate (config.json editor=aurscan-gate + editmenu=true), which
-- runs the Claude PKGBUILD scan transparently — no `alias yay=syay` needed.
-- See docs/my-setup.md, "yay 13.0 integration".

-- Options
yay.opt.diff_menu   = true
yay.opt.edit_menu   = true    -- REQUIRED: makes yay invoke the editor-gate (aurscan-gate) per PKGBUILD
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

-- Static pattern check before build (complements aurscan)
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
