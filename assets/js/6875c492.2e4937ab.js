"use strict";(self.webpackChunkcloudflare=self.webpackChunkcloudflare||[]).push([[8610],{6341:(e,t,a)=>{a.d(t,{Z:()=>s});var l=a(9496),n=a(6880),r=a(3465);function s(e){const{metadata:t}=e,{previousPage:a,nextPage:s}=t;return l.createElement("nav",{className:"pagination-nav","aria-label":(0,n.I)({id:"theme.blog.paginator.navAriaLabel",message:"Blog list page navigation",description:"The ARIA label for the blog pagination"})},a&&l.createElement(r.Z,{permalink:a,title:l.createElement(n.Z,{id:"theme.blog.paginator.newerEntries",description:"The label used to navigate to the newer blog posts page (previous page)"},"Newer Entries")}),s&&l.createElement(r.Z,{permalink:s,title:l.createElement(n.Z,{id:"theme.blog.paginator.olderEntries",description:"The label used to navigate to the older blog posts page (next page)"},"Older Entries"),isNext:!0}))}},8521:(e,t,a)=>{a.d(t,{Z:()=>s});var l=a(9496),n=a(3441),r=a(9362);function s(e){let{items:t,component:a=r.Z}=e;return l.createElement(l.Fragment,null,t.map((e=>{let{content:t}=e;return l.createElement(n.n,{key:t.metadata.permalink,content:t},l.createElement(a,null,l.createElement(t,null)))})))}},4981:(e,t,a)=>{a.r(t),a.d(t,{default:()=>E});var l=a(9496),n=a(5924),r=a(6880),s=a(2827),o=a(432),i=a(214),g=a(9480),c=a(4847),m=a(6341),u=a(8649),p=a(8521);function d(e){const t=function(){const{selectMessage:e}=(0,s.c)();return t=>e(t,(0,r.I)({id:"theme.blog.post.plurals",description:'Pluralized label for "{count} posts". Use as much plural forms (separated by "|") as your language support (see https://www.unicode.org/cldr/cldr-aux/charts/34/supplemental/language_plural_rules.html)',message:"One post|{count} posts"},{count:t}))}();return(0,r.I)({id:"theme.blog.tagTitle",description:"The title of the page for a blog tag",message:'{nPosts} tagged with "{tagName}"'},{nPosts:t(e.count),tagName:e.label})}function h(e){let{tag:t}=e;const a=d(t);return l.createElement(l.Fragment,null,l.createElement(o.d,{title:a}),l.createElement(u.Z,{tag:"blog_tags_posts"}))}function b(e){let{tag:t,items:a,sidebar:n,listMetadata:s}=e;const o=d(t);return l.createElement(c.Z,{sidebar:n},l.createElement("header",{className:"margin-bottom--xl"},l.createElement("h1",null,o),l.createElement(g.Z,{href:t.allTagsPath},l.createElement(r.Z,{id:"theme.tags.tagsPageLink",description:"The label of the link targeting the tag list page"},"View All Tags"))),l.createElement(p.Z,{items:a}),l.createElement(m.Z,{metadata:s}))}function E(e){return l.createElement(o.FG,{className:(0,n.Z)(i.k.wrapper.blogPages,i.k.page.blogTagPostListPage)},l.createElement(h,e),l.createElement(b,e))}}}]);