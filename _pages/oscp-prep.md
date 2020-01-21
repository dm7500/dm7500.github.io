---
layout: collection
title: "OSCPPrep"
permalink: "/oscp-prep/"
---

{% for page in site.oscp-prep %}

<a href="{{ page.url | prepend: site.baseurl }}">
<h2>{{ page.title }}</h2>
</a>

<p class="post-excerpt">{{ page.headline | truncate: 160 }}</p>

{{page.picture}}

{% endfor %} 

<!-- <ul>
  {% for page in site.oscp-prep %}
    <li>
      <a href="{{ page.url }}">{{ page.title }}</a>
      - {{ page.headline }}
    </li>
  {% endfor %}
</ul> -->