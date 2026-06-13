import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import HomePage from './pages/HomePage'
import InvestigatePage from './pages/InvestigatePage'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<HomePage />} />
        <Route path="/investigate" element={<InvestigatePage />} />
      </Route>
    </Routes>
  )
}
