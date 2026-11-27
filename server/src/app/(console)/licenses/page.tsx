import { redirect } from 'next/navigation';

// The old license-only view is now a preset of the fleet-wide SBOM browser.
export default function LicensesPage() {
  redirect('/sbom?license=copyleft');
}
