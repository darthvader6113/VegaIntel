/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: "#f8fafc", // Crisp light slate
        surface: "#ffffff",    // Pure white
        card: "#ffffff",
        border: "#e2e8f0",     // Slate 200 border
        brand: {
          50: "#fff7ed",
          100: "#ffedd5",
          200: "#fed7aa",
          300: "#fdba74",
          400: "#fb923c",
          500: "#f97316", // Primary SaaS Orange
          600: "#ea580c", // Deep vibrant orange
          700: "#c2410c",
          800: "#9a3412",
          900: "#7c2d12",
          neon: "#ff5500",
        },
        cyber: {
          gray: "#64748b",
          dark: "#0f172a",
          green: "#16a34a",
          red: "#dc2626",
          yellow: "#d97706",
          blue: "#2563eb",
          purple: "#9333ea"
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      },
      boxShadow: {
        'glow-orange': '0 0 20px -5px rgba(249, 115, 22, 0.25)',
        'glow-orange-sm': '0 0 10px -2px rgba(249, 115, 22, 0.2)',
      }
    },
  },
  plugins: [],
}
