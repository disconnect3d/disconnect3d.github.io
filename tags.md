---
layout: page
title: Tags
permalink: /tags/
---

{% assign tags = site.tags | sort %}

<p class="tag-cloud">
{% for tag in tags %}<a href="#{{ tag[0] | slugify }}">{{ tag[0] }}</a> <span class="tag-count">({{ tag[1].size }})</span>{% unless forloop.last %} · {% endunless %}{% endfor %}
</p>

{% for tag in tags %}
## <span id="{{ tag[0] | slugify }}">{{ tag[0] }}</span>

<ul class="tag-posts">
{% for post in tag[1] %}
  <li><span class="post-date">{{ post.date | date: "%Y-%m-%d" }}</span> <a href="{{ post.url | relative_url }}">{{ post.title }}</a></li>
{% endfor %}
</ul>
{% endfor %}
