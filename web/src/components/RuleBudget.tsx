import { number } from '../format';
import type { Rule } from '../types';

export default function RuleBudget({ rule }: { rule: Rule }) {
  if (rule.action !== 'limit') return null;
  return <><div className="cell-detail">{number(rule.pps)} pps · burst {number(rule.burst)}{rule.sourcePps ? ` · IP ${number(rule.sourcePps)} pps` : ''}</div>{rule.bps ? <div className="cell-detail">Servis {number(rule.bps)} byte/s · burst {number(rule.byteBurst)} B</div> : null}{rule.sourceBps ? <div className="cell-detail">IP {number(rule.sourceBps)} byte/s · burst {number(rule.sourceByteBurst)} B</div> : null}</>;
}
