import { CRITICALITY, EXPOSURE } from '@/lib/systemmeta';
import { saveSystem } from '../actions';

export interface SystemFormValues {
  id?: number;
  hostId?: string;
  root?: string;
  name?: string;
  exposure?: string;
  criticality?: string;
  url?: string;
  owner?: string;
  stack?: string;
  detectedStack?: string;
  note?: string;
  ignored?: boolean;
  origin?: string;
}

function Row({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block font-medium">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

// The same form documents what a "system" is: where it lives and how much it matters.
export function SystemForm({ v, hosts }: { v: SystemFormValues; hosts?: { id: string; name: string }[] }) {
  const isOs = v.root === '__os__';
  return (
    <form action={saveSystem} className="grid gap-4 md:grid-cols-2">
      {v.id && <input type="hidden" name="id" value={v.id} />}
      {hosts && (
        <Row label="ホスト">
          <select name="host" className="input" defaultValue={v.hostId} required>
            {hosts.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}
          </select>
        </Row>
      )}
      <Row label="システム名"><input name="name" className="input" defaultValue={v.name} required /></Row>
      {!isOs && (
        <Row label="場所（ルートディレクトリ）" hint="この配下の lockfile と venv をこのシステムのものとして扱います。登録すると、次回の報告から反映されます。">
          <input name="root" className="input font-mono" defaultValue={v.root} placeholder="/srv/apps/shop" required={!v.id} />
        </Row>
      )}
      <Row label="公開区分" hint="外部に公開しているシステムは、優先して対応すべき対象として上位に表示します。">
        <select name="exposure" className="input" defaultValue={v.exposure ?? 'unknown'}>
          {Object.entries(EXPOSURE).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
      </Row>
      <Row label="重要度">
        <select name="criticality" className="input" defaultValue={v.criticality ?? 'normal'}>
          {Object.entries(CRITICALITY).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
      </Row>
      <Row label="URL"><input name="url" className="input" defaultValue={v.url} placeholder="https://shop.example.com" /></Row>
      <Row label="担当"><input name="owner" className="input" defaultValue={v.owner} /></Row>
      <Row label="技術スタック" hint={v.detectedStack ? `自動判定：${v.detectedStack}（空欄なら自動判定を表示）` : '空欄なら依存パッケージから自動で判定します。'}>
        <input name="stack" className="input" defaultValue={v.stack} placeholder={v.detectedStack} />
      </Row>
      <Row label="監視">
        <span className="flex items-center gap-2"><input type="checkbox" name="monitored" defaultChecked={!v.ignored} /> 脆弱性を数え、通知する（外すと「除外」）</span>
      </Row>
      <div className="md:col-span-2"><Row label="メモ"><textarea name="note" rows={3} className="input" defaultValue={v.note} /></Row></div>
      <div className="flex items-center gap-3 md:col-span-2">
        <button className="btn">{v.id ? '保存' : '登録'}</button>
        {v.origin && <span className="text-xs text-muted">{v.origin === 'manual' ? '手動で登録したシステム' : '自動で検出したシステム（保存すると場所を手動で固定できます）'}</span>}
      </div>
    </form>
  );
}
