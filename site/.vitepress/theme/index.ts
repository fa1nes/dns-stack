import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import ArchDiagram from './ArchDiagram.vue'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('ArchDiagram', ArchDiagram)
  }
} satisfies Theme
