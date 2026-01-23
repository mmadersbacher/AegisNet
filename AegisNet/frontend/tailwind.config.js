/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                background: '#0B1121', // Darker, richer background
                surface: '#151E32',    // Slightly lighter for cards
                aegis: {
                    50: '#F0F5FF',
                    100: '#E0EAFF',
                    500: '#3B82F6',
                    600: '#2563EB',
                    accent: '#00F0FF', // Cyber Cyan
                }
            },
            fontFamily: {
                sans: ['"Inter"', 'sans-serif'],
                mono: ['"JetBrains Mono"', 'monospace'],
            },
            backgroundImage: {
                'grid-pattern': "linear-gradient(to right, #1e293b 1px, transparent 1px), linear-gradient(to bottom, #1e293b 1px, transparent 1px)",
                'radial-gradient': 'radial-gradient(circle at center, var(--tw-gradient-stops))',
            },
            backdropBlur: {
                xs: '2px',
            }
        },
    },
    plugins: [],
}
