# 01 — Global shell and navigation

## Scope

Primary navigation, active states, header geometry, keyboard bypass, responsive wrapping, theme control, and continuity between application, editorial, calculator, policy, and ticker pages.

## Findings

### Fixed: public pages felt like a separate website

Blog, research process, data sources, compound calculator, privacy, terms, and stock landing pages retained an older “Back to platform” header. This broke product continuity and made About/LensScore feel detached from the rest of the product.

Correction:

- Installed the same nine destinations everywhere: Home, Market, Research, LensScore, Projections, Planner, Learn, Saved, and About.
- Retired the old public-page header while retaining its markup as hidden compatibility structure.
- Added a consistent theme control.
- Added a keyboard-visible “Skip to content” link and explicit main-content target.

### Fixed: narrow-screen controls were inconsistent

Several page-specific controls measured 34–38 pixels high. They worked, but did not meet the release interaction target.

Correction:

- Enforced a 44-pixel minimum interaction height for the audited mobile product controls.
- Preserved the compact visual density while increasing the usable hit area.
- Reflowed the research shell search and actions into one readable mobile column.

## Re-audit

- Desktop/light: all nine navigation items remained on one 56-pixel row on audited product and public pages.
- Mobile/dark: no horizontal page overflow and no audited control below 40 pixels; intended release target is 44 pixels.
- Active and inactive tabs preserve identical geometry.
- All audited public product pages expose the shared navigation and keyboard skip link.

## Intentional behavior

Login, signup, reset-password, and verification pages keep the focused account shell rather than the full product navigation. Removing exit distractions is appropriate inside authentication flows.

