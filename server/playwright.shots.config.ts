import base from './playwright.config';

// Mobile screenshot run: npx playwright test -c playwright.shots.config.ts
export default { ...base, testDir: './tests/shots', reporter: 'line' };
