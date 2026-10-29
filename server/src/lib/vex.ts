// CycloneDX VEX "justification" values for findings marked not_affected.
export const VEX_JUSTIFICATIONS = [
  'code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency', 'requires_environment',
  'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter', 'protected_by_mitigating_control',
] as const;

export const VEX_LABEL: Record<string, string> = {
  code_not_present: '該当コードが含まれていない',
  code_not_reachable: '該当コードに到達しない',
  requires_configuration: '特定の設定が必要（該当しない）',
  requires_dependency: '特定の依存が必要（該当しない）',
  requires_environment: '特定の環境が必要（該当しない）',
  protected_by_compiler: 'コンパイラで保護されている',
  protected_at_runtime: '実行時に保護されている',
  protected_at_perimeter: '境界（WAF等）で保護されている',
  protected_by_mitigating_control: '他の対策で緩和されている',
};
