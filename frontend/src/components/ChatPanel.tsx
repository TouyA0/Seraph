import { useState, useRef, useEffect } from 'react'
import styles from './ChatPanel.module.css'

interface Message {
  role: 'user' | 'assistant'
  content: string
}

interface Props {
  investigationId: string
  onClose: () => void
}

export default function ChatPanel({ investigationId, onClose }: Props) {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [streaming, setStreaming] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const abortRef = useRef<AbortController>()

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = async () => {
    const text = input.trim()
    if (!text || streaming) return
    setInput('')

    const userMsg: Message = { role: 'user', content: text }
    const history = [...messages, userMsg]
    setMessages(history)
    setStreaming(true)

    const assistantMsg: Message = { role: 'assistant', content: '' }
    setMessages([...history, assistantMsg])

    abortRef.current = new AbortController()
    try {
      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          investigation_id: investigationId,
          messages: history,
        }),
        signal: abortRef.current.signal,
      })

      const reader = res.body!.getReader()
      const decoder = new TextDecoder()
      let accumulated = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        const chunk = decoder.decode(value)
        for (const line of chunk.split('\n')) {
          if (!line.startsWith('data: ')) continue
          const data = line.slice(6)
          if (data === '[DONE]') break
          try {
            const parsed = JSON.parse(data)
            if (parsed.content) {
              accumulated += parsed.content
              setMessages((prev) => {
                const next = [...prev]
                next[next.length - 1] = { role: 'assistant', content: accumulated }
                return next
              })
            }
          } catch {
            // ignore parse errors
          }
        }
      }
    } catch (e: unknown) {
      if ((e as Error).name !== 'AbortError') {
        setMessages((prev) => {
          const next = [...prev]
          next[next.length - 1] = { role: 'assistant', content: 'Erreur : IA non disponible.' }
          return next
        })
      }
    } finally {
      setStreaming(false)
    }
  }

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() }
  }

  return (
    <div className={styles.panel}>
      <div className={styles.header}>
        <div className={styles.headerTitle}>
          <span className={styles.headerDot} />
          Chat IA
        </div>
        <button className={styles.closeBtn} onClick={onClose}>✕</button>
      </div>

      <div className={styles.messages}>
        {messages.length === 0 && (
          <div className={styles.empty}>
            Posez une question sur cette investigation.<br />
            <span>Ex : « Pourquoi cette IP est-elle critique ? »</span>
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`${styles.msg} ${m.role === 'user' ? styles.msgUser : styles.msgAssistant}`}>
            <div className={styles.msgRole}>{m.role === 'user' ? 'Vous' : 'Seraph IA'}</div>
            <div className={styles.msgContent}>
              {m.content}
              {streaming && i === messages.length - 1 && m.role === 'assistant' && (
                <span className={styles.cursor} />
              )}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      <div className={styles.inputWrap}>
        <textarea
          className={styles.input}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Votre question… (Entrée pour envoyer)"
          rows={2}
          disabled={streaming}
        />
        <button
          className={styles.sendBtn}
          onClick={send}
          disabled={!input.trim() || streaming}
        >
          {streaming ? '…' : '↑'}
        </button>
      </div>
    </div>
  )
}
