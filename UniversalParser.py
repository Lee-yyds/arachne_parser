#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from typing import List, Dict, Any, Union
import parsel
from jsonpath_ng import parse as jsonpath_parse


class UniversalParser:
    """
    通用解析器，支持xpath和jsonpath的链式解析、嵌套数据提取
    """
    
    def __init__(self):
        pass
    
    def parse(self, content: str, config: List[Dict], content_type: str = 'html', clean_text: bool = True) -> Dict[str, Any]:
        """
        根据配置解析内容
        
        Args:
            content: 要解析的内容（HTML或JSON字符串）
            config: 解析配置
            content_type: 内容类型，'html' 或 'json'
            clean_text: 是否清理文本内容（去除多余空白字符）
        
        Returns:
            解析结果字典
        """
        result = {}
        
        for rule_config in config:
            if content_type == 'html':
                selector = parsel.Selector(text=content)
                parsed_data = self._parse_html_rules(selector, rule_config)
            else:
                json_data = json.loads(content) if isinstance(content, str) else content
                parsed_data = self._parse_json_rules(json_data, rule_config)
            
            # 如果配置中有name，则使用它作为key
            if 'name' in rule_config:
                result[rule_config['name']] = parsed_data
            else:
                result.update(parsed_data)
        
        # 清理文本内容
        if clean_text:
            result = self._clean_text(result)
        
        return result
    
    def _parse_html_rules(self, selector: parsel.Selector, config: Dict) -> Union[List, Dict, str]:
        """解析HTML规则"""
        if 'xpath' in config:
            # 使用xpath选择元素
            if '/@' in config['xpath']:
                # 属性选择器，直接获取字符串值
                elements = selector.xpath(config['xpath']).getall()
                is_attribute_selector = True
            else:
                # 普通元素选择器
                elements = selector.xpath(config['xpath'])
                is_attribute_selector = False
            
            if 'name' in config and 'rules' in config:
                # 既有name又有rules：将rules的解析结果保存到name指定的key中
                sub_results = []
                for element in elements:
                    item_result = {}
                    for rule in config['rules']:
                        # 检查是否需要处理JSON内容
                        if 'xpath' in rule and rule['xpath'].endswith('/text()') and 'rules' in rule:
                            # 这可能是JSON内容，先提取文本然后解析
                            json_text = element.xpath(rule['xpath']).get()
                            if json_text:
                                try:
                                    json_data = json.loads(json_text)
                                    # 对JSON数据应用子规则
                                    for sub_rule in rule['rules']:
                                        if 'name' in sub_rule:
                                            json_result = self._parse_json_rules(json_data, sub_rule)
                                            item_result[sub_rule['name']] = json_result
                                except json.JSONDecodeError:
                                    pass
                        else:
                            sub_result = self._parse_html_rules(element, rule)
                            if 'name' in rule:
                                item_result[rule['name']] = sub_result
                            else:
                                # 如果子规则没有name，将结果合并到当前层级
                                if isinstance(sub_result, dict):
                                    item_result.update(sub_result)
                                elif isinstance(sub_result, list):
                                    for item in sub_result:
                                        if isinstance(item, dict):
                                            item_result.update(item)
                    sub_results.append(item_result)
                
                # 如果只有一个元素，返回单个对象；否则返回数组
                if len(sub_results) == 1:
                    return sub_results[0]
                else:
                    return sub_results
                    
            elif 'name' in config:
                # 只有name字段，直接保存结果
                if is_attribute_selector:
                    # 属性值已经是字符串，直接返回
                    return elements
                elif config['xpath'].endswith('//text()'):
                    # 文本节点，合并成单个字符串
                    all_texts = [elem.get() for elem in elements]
                    return ''.join(all_texts).strip()
                else:
                    # 元素对象，需要提取值
                    if len(elements) == 1:
                        return self._extract_value(elements[0])
                    else:
                        return [self._extract_value(elem) for elem in elements]
                    
            elif 'rules' in config:
                # 只有rules字段，继续向下解析
                results = []
                for element in elements:
                    item_result = {}
                    for rule in config['rules']:
                        # 检查是否需要处理JSON内容
                        if 'xpath' in rule and rule['xpath'].endswith('/text()') and 'rules' in rule:
                            # 这可能是JSON内容，先提取文本然后解析
                            json_text = element.xpath(rule['xpath']).get()
                            if json_text:
                                try:
                                    json_data = json.loads(json_text)
                                    # 对JSON数据应用子规则
                                    for sub_rule in rule['rules']:
                                        if 'name' in sub_rule:
                                            json_result = self._parse_json_rules(json_data, sub_rule)
                                            item_result[sub_rule['name']] = json_result
                                except json.JSONDecodeError:
                                    pass
                        else:
                            sub_result = self._parse_html_rules(element, rule)
                            if 'name' in rule:
                                item_result[rule['name']] = sub_result
                            else:
                                # 如果子规则没有name，将结果合并到当前层级
                                if isinstance(sub_result, dict):
                                    item_result.update(sub_result)
                                elif isinstance(sub_result, list):
                                    for item in sub_result:
                                        if isinstance(item, dict):
                                            item_result.update(item)
                    results.append(item_result)
                return results
            else:
                # 只有xpath，没有name和rules，直接返回匹配的元素内容
                if is_attribute_selector:
                    # 属性值已经是字符串，直接返回
                    return elements
                else:
                    # 元素对象，需要提取值
                    if len(elements) == 1:
                        return self._extract_value(elements[0])
                    else:
                        return [self._extract_value(elem) for elem in elements]
        
        elif ('name' in config or 'name' in config) and 'rules' in config:
            # 只有name/name和rules，没有xpath的情况 - name作为key，值是rules解析结果
            return self._parse_rules_with_context(selector, config['rules'])
        
        elif 'jsonpath' in config:
            # 处理嵌入在HTML中的JSON数据
            json_text = selector.get()
            if json_text:
                try:
                    json_data = json.loads(json_text)
                    return self._parse_json_rules(json_data, config)
                except json.JSONDecodeError:
                    return None
        
        return None
    
    def _parse_rules_with_context(self, selector: parsel.Selector, rules: List[Dict]) -> Dict:
        """
        处理只有rules，没有顶层xpath的情况
        先处理没有name的rule作为上下文，然后在上下文中应用有name的rules
        """
        result = {}
        
        for rule in rules:
            if 'name' in rule:
                # 有name的规则，直接解析
                if 'xpath' in rule:
                    # 普通的xpath规则
                    sub_result = self._parse_html_rules(selector, rule)
                    result[rule['name']] = sub_result
                elif 'rules' in rule:
                    # 嵌套的rules，需要特殊处理
                    nested_result = self._parse_nested_rules(selector, rule['rules'])
                    result[rule['name']] = nested_result
        
        return result
    
    def _parse_nested_rules(self, selector: parsel.Selector, rules: List[Dict]) -> List[Dict]:
        """
        处理嵌套的rules，特别是celebrities这种情况
        """
        context_elements = None
        named_rules = []
        
        # 分离上下文规则和命名规则
        for rule in rules:
            if 'name' not in rule and 'xpath' in rule:
                # 没有name的rule作为上下文
                context_elements = selector.xpath(rule['xpath'])
            elif 'name' in rule and 'xpath' in rule:
                named_rules.append(rule)
        
        if not context_elements:
            # 如果没有上下文规则，直接在当前selector上应用named_rules
            context_elements = [selector]
        
        results = []
        
        # 对每个上下文元素，处理两种情况：
        # 1. 上下文元素就是目标元素（如comment-item）
        # 2. 上下文元素是容器，需要找到内部的目标元素（如celebrities容器）
        for context_element in context_elements:
            # 尝试直接在上下文元素上应用规则
            item_result = {}
            has_valid_result = False
            
            for rule in named_rules:
                sub_result = self._parse_html_rules(context_element, rule)
                if sub_result is not None and sub_result != [] and sub_result != "":
                    item_result[rule['name']] = sub_result
                    has_valid_result = True
                else:
                    item_result[rule['name']] = sub_result
            
            # 如果直接应用规则有效，添加结果
            if has_valid_result:
                results.append(item_result)
            else:
                # 如果直接应用无效，尝试在子元素上应用规则
                # 查找可能的子元素（li, div等常见容器）
                child_elements = context_element.xpath('.//*[self::li or self::div[@class] or self::article or self::section]')
                
                for child_element in child_elements:
                    child_result = {}
                    child_has_valid = False
                    
                    for rule in named_rules:
                        sub_result = self._parse_html_rules(child_element, rule)
                        if sub_result is not None and sub_result != [] and sub_result != "":
                            child_result[rule['name']] = sub_result
                            child_has_valid = True
                        else:
                            child_result[rule['name']] = sub_result
                    
                    if child_has_valid:
                        results.append(child_result)
        
        return results
    
    def _find_matching_elements(self, context: parsel.Selector, named_rules: List[Dict]) -> List[parsel.Selector]:
        """
        在给定上下文中找到能匹配所有命名规则的元素
        """
        if not named_rules:
            return []
        
        # 获取第一个规则的xpath，用来找候选元素
        first_rule_xpath = named_rules[0].get('xpath', '')
        if not first_rule_xpath:
            return []
        
        # 分析xpath来找到候选元素
        # 如果xpath以 "./" 开头，我们需要找到合适的父元素
        if first_rule_xpath.startswith('./'):
            # 尝试找到能匹配这个相对xpath的元素
            # 我们需要推断出应该在哪些元素上应用这个xpath
            
            # 策略：尝试在上下文的所有子元素上应用第一个规则，看哪些能成功
            candidate_elements = []
            
            # 获取所有可能的子元素
            all_descendants = context.xpath('.//*')
            
            for element in all_descendants:
                # 检查这个元素是否能匹配第一个规则
                try:
                    test_result = element.xpath(first_rule_xpath)
                    if test_result:
                        # 进一步检查是否能匹配所有规则
                        can_match_all = True
                        for rule in named_rules:
                            rule_xpath = rule.get('xpath', '')
                            if rule_xpath and not element.xpath(rule_xpath):
                                can_match_all = False
                                break
                        
                        if can_match_all:
                            candidate_elements.append(element)
                except:
                    continue
            
            return candidate_elements
        else:
            # 绝对xpath，直接在上下文中查找
            try:
                return context.xpath(first_rule_xpath)
            except:
                return []
    
    def _parse_json_rules(self, json_data: Any, config: Dict) -> Any:
        """解析JSON规则"""
        if 'jsonpath' in config:
            # 使用jsonpath选择数据
            jsonpath_expr = jsonpath_parse(config['jsonpath'])
            matches = [match.value for match in jsonpath_expr.find(json_data)]
            
            if 'name' in config and 'rules' in config:
                # 既有name又有rules：将rules的解析结果保存到name指定的key中
                sub_results = []
                for match in matches:
                    item_result = {}
                    for rule in config['rules']:
                        sub_result = self._parse_json_rules(match, rule)
                        if 'name' in rule:
                            item_result[rule['name']] = sub_result
                        else:
                            if isinstance(sub_result, dict):
                                item_result.update(sub_result)
                            elif isinstance(sub_result, list):
                                for item in sub_result:
                                    if isinstance(item, dict):
                                        item_result.update(item)
                    sub_results.append(item_result)
                
                # 如果只有一个元素，返回单个对象；否则返回数组
                if len(sub_results) == 1:
                    return sub_results[0]
                else:
                    return sub_results
                    
            elif 'name' in config:
                # 只有name字段，直接保存结果
                if len(matches) == 1:
                    return matches[0]
                else:
                    return matches
                    
            elif 'rules' in config:
                # 只有rules字段，继续向下解析
                results = []
                for match in matches:
                    item_result = {}
                    for rule in config['rules']:
                        sub_result = self._parse_json_rules(match, rule)
                        if 'name' in rule:
                            item_result[rule['name']] = sub_result
                        else:
                            if isinstance(sub_result, dict):
                                item_result.update(sub_result)
                            elif isinstance(sub_result, list):
                                for item in sub_result:
                                    if isinstance(item, dict):
                                        item_result.update(item)
                    results.append(item_result)
                return results
            else:
                # 只有jsonpath，没有name和rules，直接返回匹配的数据
                if len(matches) == 1:
                    return matches[0]
                else:
                    return matches
        
        elif 'xpath' in config and 'rules' in config:
            # 处理混合解析：先xpath后jsonpath
            return self._parse_mixed_rules(json_data, config)
        
        return json_data
    
    def _parse_mixed_rules(self, selector_or_data: Any, config: Dict) -> Any:
        """处理混合解析规则（xpath + jsonpath）"""
        if isinstance(selector_or_data, parsel.Selector):
            # 继续使用xpath
            return self._parse_html_rules(selector_or_data, config)
        else:
            # 切换到jsonpath
            return self._parse_json_rules(selector_or_data, config)
    
    def _clean_text(self, text: Any) -> Any:
        """清理文本内容，将换行符和多个空白字符替换为单个空格"""
        if isinstance(text, str):
            # 将换行符、制表符、多个空格替换为单个空格
            cleaned = re.sub(r'\s+', ' ', text.strip())
            return cleaned if cleaned else None  # 空字符串返回None，稍后会被过滤
        elif isinstance(text, list):
            # 递归清理列表中的每个元素，并过滤掉空值
            cleaned_list = []
            for item in text:
                cleaned_item = self._clean_text(item)
                if cleaned_item is not None and cleaned_item != "":
                    cleaned_list.append(cleaned_item)
            return cleaned_list
        elif isinstance(text, dict):
            # 递归清理字典中的每个值
            return {key: self._clean_text(value) for key, value in text.items()}
        else:
            # 其他类型直接返回
            return text

    def _extract_value(self, element: parsel.Selector) -> str:
        """从元素中提取值"""
        try:
            # 检查selector类型
            if hasattr(element, 'type') and element.type == 'json':
                # 如果是JSON类型，直接返回内容
                return element.get()
            
            # 首先尝试获取文本内容
            text = element.xpath('.//text()').get()
            if text and text.strip():
                return text.strip()
            
            # 如果没有文本，尝试获取属性值
            for attr in ['data-id', 'id', 'value', 'href', 'src']:
                value = element.xpath(f'.//@{attr}').get()
                if value:
                    return value
            
            # 最后返回整个HTML
            return element.get()
        except ValueError:
            # 如果xpath调用失败，直接返回原始内容
            return element.get()


def demo():
    """演示用法"""
    # 读取HTML文件
    with open('1.html', 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # 配置示例：解析行星信息
    parse_config = [
        {
            "name": "movie",
            # "xpath": "//div[@id='link-report-intra']/span//text()",
            "rules": [
                {
                    "name": "info",
                    "xpath": "//div[@id='info']//text()"
                },{
                    "name": "instruction",
                    "xpath": "//div[@id='link-report-intra']/span//text()"
                },
                {
                    "name":"celebrities",
                    "rules": [
                        {
                            "xpath": "//div[@id='celebrities']"
                        },
                        {
                            "name": "actor_name",
                            "xpath": "./div[@class='info']/span[@class='name']",

                        }, {
                            "name": "actor_role",
                            "xpath": "./div[@class='info']/span[@class='role']",

                        }
                    ]
                },{
                    "name": "pics",
                    "xpath": "//ul[contains(@class, 'related-pic-bd')]//a/@href"
                },{
                    "name": "short_comments",
                    "rules":[
                        {
                        "xpath": "//div[@id='hot-comments']/div[@class='comment-item'][*]"
                    },{
                        "name": "comment",
                        "xpath": ".//div[@class='comment']/p[@class='comment-content']//text()"
                    },{
                        "name": "comment_name",
                        "xpath": ".//div[@class='comment']/h3/span[@class='comment-info']/a//text()"
                    }]

                },{
                    "name": "long_comments",
                    "rules":[
                        {
                        "xpath": "//div[@class='main review-item'][*]"
                    },{
                        "name": "comment",
                        "xpath": ".//div[@class='short-content']//text()"
                    },{
                        "name": "comment_name",
                        "xpath": ".//header[@class='main-hd']/a[@class='name']//text()"
                    }]
                }
            ]
        }
    ]
    
    # 创建解析器并解析
    parser = UniversalParser()
    result = parser.parse(html_content, parse_config, 'html')
    
    # 输出结果
    print("解析结果:")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    
    return result




if __name__ == "__main__":
    demo()
    
    # print("\n=== 高级嵌套解析 ===")
    # demo_advanced()
