//
//  Utilities.swift
//  
//
//  Created by Sebastian Toivonen on 8.8.2021.
//

public extension Array where Element: FixedWidthInteger {
  static func random(count: Int) -> Self {
    var result = Array<Element>()
    result.reserveCapacity(count)
    for _ in 0..<count {
      result.append(Element.random(in: Element.min ... Element.max))
    }
    return result
  }

  static func random(count: Int, range: Range<Element>) -> Self {
      var result = Array<Element>()
      result.reserveCapacity(count)
      for _ in 0..<count {
          result.append(Element.random(in: range))
      }
      return result
  }

  static func random(count: Int, range: ClosedRange<Element>) -> Self {
      var result = Array<Element>()
      result.reserveCapacity(count)
      for _ in 0..<count {
          result.append(Element.random(in: range))
      }
      return result
  }
}
