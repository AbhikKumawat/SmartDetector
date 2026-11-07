import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        cyber: {
          950: "#050811",
          900: "#0b0f19",
          850: "#101626",
          800: "#161f36",
          700: "#243154",
          600: "#384a75",
        },
        sentinel: {
          cyan: "#00f0ff",
          emerald: "#10b981",
          red: "#ff2a5f",
          amber: "#f59e0b",
          purple: "#a855f7",
        }
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Courier New", "monospace"],
      }
    },
  },
  plugins: [],
};
export default config;
