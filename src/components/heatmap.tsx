import { IMPACT, LEVEL_STYLE, LIKELIHOOD, level } from '@/lib/risk'

// 5 x 5 likelihood by impact matrix. counts is keyed "likelihood-impact".
export function Heatmap({ counts }: { counts?: Record<string, number> }) {
  return (
    <div>
      <table className="w-full table-fixed border-separate border-spacing-1 text-xs">
        <caption className="sr-only">Risk matrix, likelihood by impact</caption>
        <thead className="table-footer-group">
          <tr>
            <td className="w-5" />
            {[1, 2, 3, 4, 5].map((i) => <th key={i} scope="col" className="font-normal text-faint">{i}<span className="sr-only">, {IMPACT[i - 1]} impact</span></th>)}
          </tr>
        </thead>
        <tbody>
          {[5, 4, 3, 2, 1].map((l) => (
            <tr key={l}>
              <th scope="row" className="font-normal text-faint">{l}<span className="sr-only">, {LIKELIHOOD[l - 1]} likelihood</span></th>
              {[1, 2, 3, 4, 5].map((i) => {
                const s = l * i
                const n = counts?.[`${l}-${i}`] ?? 0
                return (
                  <td key={i} className="p-0">
                    <div title={`${LIKELIHOOD[l - 1]} x ${IMPACT[i - 1]} = ${s}`} className={`relative grid aspect-[4/3] place-items-center rounded-md font-bold tabular-nums ${LEVEL_STYLE[level(s)]}`}>
                      <span aria-hidden className="absolute left-1 top-0.5 text-[0.625rem] font-semibold">{level(s)[0]}</span>
                      <span aria-hidden>{counts ? n || '' : s}</span>
                      <span className="sr-only">{counts ? `${n} risks` : `score ${s}`}, {level(s)}</span>
                    </div>
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-2 text-center text-xs text-faint">Likelihood (up) by impact (across). Low 1-7, Medium 8-14, High 15-25.</p>
    </div>
  )
}
