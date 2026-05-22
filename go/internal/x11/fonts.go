//go:build x11

package x11

import (
	"fmt"
	"strconv"
	"strings"
)

// MapX11FontToCSS converts an X11 font name (XLFD) to CSS font properties.
// This is a simplified implementation.
func MapX11FontToCSS(x11FontName string) (size, family, weight, slant, cssFont string) {
	// Default values
	size = "12px"
	family = "monospace"
	weight = "normal"
	slant = "normal"

	// Handle common aliases first
	switch strings.ToLower(x11FontName) {
	case "fixed", "cursor":
		size = "12px"
		family = "monospace"
		weight = "normal"
		slant = "normal"
	case "5x7", "5x8", "6x9", "6x10", "6x12", "6x13", "7x13", "7x14", "8x13", "8x16", "9x15", "9x18", "10x20", "12x24":
		// Extract height from name (e.g. "9x15" -> 15px)
		parts := strings.Split(x11FontName, "x")
		if len(parts) == 2 {
			if h, err := strconv.Atoi(parts[1]); err == nil {
				size = fmt.Sprintf("%dpx", h)
			}
		} else {
			size = "12px"
		}
		family = "monospace"
		weight = "normal"
		slant = "normal"
	case "variable":
		size = "12px"
		family = "sans-serif"
		weight = "normal"
		slant = "normal"
	case "lucidasans-10":
		size = "10px"
		family = "sans-serif"
		weight = "normal"
		slant = "normal"
	case "lucidasans-12":
		size = "12px"
		family = "sans-serif"
		weight = "normal"
		slant = "normal"
	case "lucidasans-14":
		size = "14px"
		family = "sans-serif"
		weight = "normal"
		slant = "normal"
	case "lucidasans-bold-10":
		size = "10px"
		family = "sans-serif"
		weight = "bold"
		slant = "normal"
	case "lucidasans-bold-12":
		size = "12px"
		family = "sans-serif"
		weight = "bold"
		slant = "normal"
	case "lucidasans-bold-14":
		size = "14px"
		family = "sans-serif"
		weight = "bold"
		slant = "normal"
	case "dejavu sans mono-10":
		size = "10px"
		family = "monospace"
		weight = "normal"
		slant = "normal"
	case "dejavu sans mono-12":
		size = "12px"
		family = "monospace"
		weight = "normal"
		slant = "normal"
	case "dejavu sans mono-14":
		size = "14px"
		family = "monospace"
		weight = "normal"
		slant = "normal"
	case "dejavu sans mono-bold-10":
		size = "10px"
		family = "monospace"
		weight = "bold"
		slant = "normal"
	case "dejavu sans mono-bold-12":
		size = "12px"
		family = "monospace"
		weight = "bold"
		slant = "normal"
	case "dejavu sans mono-bold-14":
		size = "14px"
		family = "monospace"
		weight = "bold"
		slant = "normal"
	}

	// Example XLFD: -*-helvetica-medium-r-normal-*-12-*-*-*-p-*-iso8859-1
	// Field indices (1-based in spec, mapped to parts index):
	// 2: Family
	// 3: Weight
	// 4: Slant
	// 7: Pixel Size
	// 8: Point Size
	parts := strings.Split(x11FontName, "-")

	// Attempt to parse XLFD
	if len(parts) >= 14 {
		// Pixel Size (Field 7)
		if len(parts[7]) > 0 && parts[7] != "*" && parts[7] != "0" {
			size = parts[7] + "px"
		} else if len(parts[8]) > 0 && parts[8] != "*" && parts[8] != "0" {
			// Point Size (Field 8), in decipoints
			if pt, err := strconv.ParseFloat(parts[8], 64); err == nil {
				size = fmt.Sprintf("%.0fpx", pt/10.0)
			}
		}

		// Family (Field 2)
		if len(parts[2]) > 0 && parts[2] != "*" {
			switch strings.ToLower(parts[2]) {
			case "helvetica", "arial", "sans":
				family = "Arial, Helvetica, sans-serif"
			case "lucida", "lucidasans":
				family = "\"Lucida Sans\", \"Lucida Sans Unicode\", sans-serif"
			case "times", "serif", "new century schoolbook", "utopia":
				family = "\"Times New Roman\", Times, serif"
			case "charter":
				family = "Charter, serif"
			case "courier", "typewriter", "lucidatypewriter", "mono", "fixed", "clean", "terminal":
				family = "\"Courier New\", Courier, monospace"
			default:
				// Fallback to the name itself, plus generic family
				// Try to guess if it's monospace or serif based on name? Hard.
				// Just use the name as a candidate.
				family = fmt.Sprintf("%q, monospace", parts[2])
			}
		} else {
			family = "monospace"
		}

		// Weight (Field 3)
		if len(parts[3]) > 0 && parts[3] != "*" {
			switch strings.ToLower(parts[3]) {
			case "medium", "regular":
				weight = "normal"
			case "bold", "demibold", "black":
				weight = "bold"
			case "light":
				weight = "lighter"
			}
		}

		// Slant (Field 4)
		if len(parts[4]) > 0 && parts[4] != "*" {
			switch strings.ToLower(parts[4]) {
			case "r": // Roman
				slant = "normal"
			case "i": // Italic
				slant = "italic"
			case "o": // Oblique
				slant = "oblique"
			}
		}
	}

	// Construct the CSS font string
	cssFont = fmt.Sprintf("%s %s %s %s", weight, slant, size, family)
	return
}

// GetAvailableFonts returns a hardcoded list of X11 font names.
func GetAvailableFonts() []string {
	return []string{
		// Adobe Courier
		"-adobe-courier-bold-o-normal--10-100-75-75-m-60-iso8859-1",
		"-adobe-courier-bold-o-normal--11-80-100-100-m-60-iso8859-1",
		"-adobe-courier-bold-o-normal--12-120-75-75-m-70-iso8859-1",
		"-adobe-courier-bold-o-normal--14-140-75-75-m-90-iso8859-1",
		"-adobe-courier-bold-o-normal--18-180-75-75-m-110-iso8859-1",
		"-adobe-courier-bold-o-normal--24-240-75-75-m-150-iso8859-1",
		"-adobe-courier-bold-r-normal--10-100-75-75-m-60-iso8859-1",
		"-adobe-courier-bold-r-normal--11-80-100-100-m-60-iso8859-1",
		"-adobe-courier-bold-r-normal--12-120-75-75-m-70-iso8859-1",
		"-adobe-courier-bold-r-normal--14-140-75-75-m-90-iso8859-1",
		"-adobe-courier-bold-r-normal--18-180-75-75-m-110-iso8859-1",
		"-adobe-courier-bold-r-normal--24-240-75-75-m-150-iso8859-1",
		"-adobe-courier-medium-o-normal--10-100-75-75-m-60-iso8859-1",
		"-adobe-courier-medium-o-normal--11-80-100-100-m-60-iso8859-1",
		"-adobe-courier-medium-o-normal--12-120-75-75-m-70-iso8859-1",
		"-adobe-courier-medium-o-normal--14-140-75-75-m-90-iso8859-1",
		"-adobe-courier-medium-o-normal--18-180-75-75-m-110-iso8859-1",
		"-adobe-courier-medium-o-normal--24-240-75-75-m-150-iso8859-1",
		"-adobe-courier-medium-r-normal--10-100-75-75-m-60-iso8859-1",
		"-adobe-courier-medium-r-normal--11-80-100-100-m-60-iso8859-1",
		"-adobe-courier-medium-r-normal--12-120-75-75-m-70-iso8859-1",
		"-adobe-courier-medium-r-normal--14-140-75-75-m-90-iso8859-1",
		"-adobe-courier-medium-r-normal--18-180-75-75-m-110-iso8859-1",
		"-adobe-courier-medium-r-normal--24-240-75-75-m-150-iso8859-1",

		// Adobe Helvetica
		"-adobe-helvetica-bold-o-normal--10-100-75-75-p-57-iso8859-1",
		"-adobe-helvetica-bold-o-normal--11-80-100-100-p-57-iso8859-1",
		"-adobe-helvetica-bold-o-normal--12-120-75-75-p-67-iso8859-1",
		"-adobe-helvetica-bold-o-normal--14-140-75-75-p-82-iso8859-1",
		"-adobe-helvetica-bold-o-normal--18-180-75-75-p-99-iso8859-1",
		"-adobe-helvetica-bold-o-normal--24-240-75-75-p-138-iso8859-1",
		"-adobe-helvetica-bold-r-normal--10-100-75-75-p-57-iso8859-1",
		"-adobe-helvetica-bold-r-normal--11-80-100-100-p-57-iso8859-1",
		"-adobe-helvetica-bold-r-normal--12-120-75-75-p-67-iso8859-1",
		"-adobe-helvetica-bold-r-normal--14-140-75-75-p-82-iso8859-1",
		"-adobe-helvetica-bold-r-normal--18-180-75-75-p-99-iso8859-1",
		"-adobe-helvetica-bold-r-normal--24-240-75-75-p-138-iso8859-1",
		"-adobe-helvetica-medium-o-normal--10-100-75-75-p-57-iso8859-1",
		"-adobe-helvetica-medium-o-normal--11-80-100-100-p-57-iso8859-1",
		"-adobe-helvetica-medium-o-normal--12-120-75-75-p-67-iso8859-1",
		"-adobe-helvetica-medium-o-normal--14-140-75-75-p-82-iso8859-1",
		"-adobe-helvetica-medium-o-normal--18-180-75-75-p-99-iso8859-1",
		"-adobe-helvetica-medium-o-normal--24-240-75-75-p-138-iso8859-1",
		"-adobe-helvetica-medium-r-normal--10-100-75-75-p-57-iso8859-1",
		"-adobe-helvetica-medium-r-normal--11-80-100-100-p-57-iso8859-1",
		"-adobe-helvetica-medium-r-normal--12-120-75-75-p-67-iso8859-1",
		"-adobe-helvetica-medium-r-normal--14-140-75-75-p-82-iso8859-1",
		"-adobe-helvetica-medium-r-normal--18-180-75-75-p-99-iso8859-1",
		"-adobe-helvetica-medium-r-normal--24-240-75-75-p-138-iso8859-1",

		// Adobe Times
		"-adobe-times-bold-i-normal--10-100-75-75-p-57-iso8859-1",
		"-adobe-times-bold-i-normal--11-80-100-100-p-57-iso8859-1",
		"-adobe-times-bold-i-normal--12-120-75-75-p-67-iso8859-1",
		"-adobe-times-bold-i-normal--14-140-75-75-p-77-iso8859-1",
		"-adobe-times-bold-i-normal--18-180-75-75-p-99-iso8859-1",
		"-adobe-times-bold-i-normal--24-240-75-75-p-132-iso8859-1",
		"-adobe-times-bold-r-normal--10-100-75-75-p-57-iso8859-1",
		"-adobe-times-bold-r-normal--11-80-100-100-p-57-iso8859-1",
		"-adobe-times-bold-r-normal--12-120-75-75-p-67-iso8859-1",
		"-adobe-times-bold-r-normal--14-140-75-75-p-77-iso8859-1",
		"-adobe-times-bold-r-normal--18-180-75-75-p-99-iso8859-1",
		"-adobe-times-bold-r-normal--24-240-75-75-p-132-iso8859-1",
		"-adobe-times-medium-i-normal--10-100-75-75-p-52-iso8859-1",
		"-adobe-times-medium-i-normal--11-80-100-100-p-52-iso8859-1",
		"-adobe-times-medium-i-normal--12-120-75-75-p-64-iso8859-1",
		"-adobe-times-medium-i-normal--14-140-75-75-p-73-iso8859-1",
		"-adobe-times-medium-i-normal--18-180-75-75-p-94-iso8859-1",
		"-adobe-times-medium-i-normal--24-240-75-75-p-124-iso8859-1",
		"-adobe-times-medium-r-normal--10-100-75-75-p-54-iso8859-1",
		"-adobe-times-medium-r-normal--11-80-100-100-p-54-iso8859-1",
		"-adobe-times-medium-r-normal--12-120-75-75-p-64-iso8859-1",
		"-adobe-times-medium-r-normal--14-140-75-75-p-73-iso8859-1",
		"-adobe-times-medium-r-normal--18-180-75-75-p-94-iso8859-1",
		"-adobe-times-medium-r-normal--24-240-75-75-p-124-iso8859-1",

		// Misc Fixed
		"-misc-fixed-bold-r-normal--13-120-75-75-c-70-iso8859-1",
		"-misc-fixed-bold-r-normal--14-130-75-75-c-70-iso8859-1",
		"-misc-fixed-bold-r-normal--15-140-75-75-c-90-iso8859-1",
		"-misc-fixed-medium-r-normal--7-70-75-75-c-50-iso8859-1",
		"-misc-fixed-medium-r-normal--8-80-75-75-c-50-iso8859-1",
		"-misc-fixed-medium-r-normal--9-90-75-75-c-60-iso8859-1",
		"-misc-fixed-medium-r-normal--10-100-75-75-c-60-iso8859-1",
		"-misc-fixed-medium-r-normal--12-120-75-75-c-60-iso8859-1",
		"-misc-fixed-medium-r-normal--13-120-75-75-c-70-iso8859-1",
		"-misc-fixed-medium-r-normal--13-120-75-75-c-80-iso8859-1",
		"-misc-fixed-medium-r-normal--14-130-75-75-c-70-iso8859-1",
		"-misc-fixed-medium-r-normal--15-140-75-75-c-90-iso8859-1",
		"-misc-fixed-medium-r-normal--18-120-100-100-c-90-iso8859-1",
		"-misc-fixed-medium-r-normal--20-200-75-75-c-100-iso8859-1",
		"-misc-fixed-medium-r-semicondensed--13-120-75-75-c-60-iso8859-1",

		// Legacy / Generic aliases
		"-*-helvetica-medium-r-normal-*-12-*-*-*-p-*-iso8859-1",
		"-*-helvetica-medium-r-normal-*-14-*-*-*-p-*-iso8859-1",
		"-*-helvetica-medium-r-normal-*-18-*-*-*-p-*-iso8859-1",
		"-*-helvetica-bold-r-normal-*-12-*-*-*-p-*-iso8859-1",
		"-*-courier-medium-r-normal-*-12-*-*-*-m-*-iso8859-1",
		"-*-courier-medium-r-normal-*-14-*-*-*-m-*-iso8859-1",
		"-*-times-medium-r-normal-*-12-*-*-*-p-*-iso8859-1",
		"-*-times-medium-r-normal-*-14-*-*-*-p-*-iso8859-1",
		"-*-lucida-medium-r-normal-*-12-*-*-*-p-*-iso8859-1",
		"-*-lucidatypewriter-medium-r-normal-*-12-*-*-*-m-*-iso8859-1",
		"-*-charter-medium-r-normal-*-12-*-*-*-p-*-iso8859-1",
		"-*-new century schoolbook-medium-r-normal-*-12-*-*-*-p-*-iso8859-1",

		"fixed",
		"variable",
		"5x7", "5x8", "6x9", "6x10", "6x12", "6x13",
		"7x13", "7x14", "8x13", "8x16", "9x15", "9x18",
		"10x20", "12x24",
		"cursor",
		"lucidasans-10",
		"lucidasans-12",
		"lucidasans-14",
		"lucidasans-bold-10",
		"lucidasans-bold-12",
		"lucidasans-bold-14",
		"dejavu sans mono-10",
		"dejavu sans mono-12",
		"dejavu sans mono-14",
		"dejavu sans mono-bold-10",
		"dejavu sans mono-bold-12",
		"dejavu sans mono-bold-14",
		"monospace",
		"sans-serif",
		"serif",
	}
}
