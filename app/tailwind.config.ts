import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/**/*.{ts,tsx,js,jsx,mdx}",
    "./node_modules/@tremor/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Redot brand
        brand: {
          DEFAULT: "#E11E27",
          50: "#FEF2F2",
          100: "#FEE5E5",
          200: "#FBC9CA",
          300: "#F69EA0",
          400: "#EE6669",
          500: "#E11E27",
          600: "#C01017",
          700: "#9F0F14",
          800: "#840E13",
          900: "#6E0F14",
        },
        ink: {
          DEFAULT: "#1F1F1F",
          muted: "#6B7280",
          subtle: "#9CA3AF",
        },
        surface: {
          DEFAULT: "#FFFFFF",
          alt: "#F8F9FA",
          card: "#FFFFFF",
        },
        border: {
          DEFAULT: "#E5E7EB",
          strong: "#D1D5DB",
        },
        // Tremor expects these to exist for charts
        tremor: {
          brand: {
            faint: "#FEE5E5",
            muted: "#FBC9CA",
            subtle: "#EE6669",
            DEFAULT: "#E11E27",
            emphasis: "#C01017",
            inverted: "#FFFFFF",
          },
          background: {
            muted: "#F8F9FA",
            subtle: "#F4F4F5",
            DEFAULT: "#FFFFFF",
            emphasis: "#1F1F1F",
          },
          border: { DEFAULT: "#E5E7EB" },
          ring: { DEFAULT: "#E5E7EB" },
          content: {
            subtle: "#9CA3AF",
            DEFAULT: "#6B7280",
            emphasis: "#374151",
            strong: "#1F1F1F",
            inverted: "#FFFFFF",
          },
        },
      },
      fontFamily: {
        sans: ["system-ui", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
      },
      boxShadow: {
        "tremor-input": "0 1px 2px 0 rgb(0 0 0 / 0.05)",
        "tremor-card": "0 1px 3px 0 rgb(0 0 0 / 0.06)",
        "tremor-dropdown": "0 4px 6px -1px rgb(0 0 0 / 0.06)",
      },
      borderRadius: {
        "tremor-small": "0.375rem",
        "tremor-default": "0.5rem",
        "tremor-full": "9999px",
      },
      fontSize: {
        "tremor-label": ["0.75rem", { lineHeight: "1rem" }],
        "tremor-default": ["0.875rem", { lineHeight: "1.25rem" }],
        "tremor-title": ["1.125rem", { lineHeight: "1.75rem" }],
        "tremor-metric": ["1.875rem", { lineHeight: "2.25rem" }],
      },
    },
  },
  plugins: [],
};

export default config;
