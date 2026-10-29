import { redirect } from 'next/navigation';

// Projects are now shown inline under each host (expand a host on /hosts). The separate list is gone.
export default function SystemsPage() {
  redirect('/hosts');
}
